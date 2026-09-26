/* SPDX-License-Identifier: Apache-2.0 */

#include "nat64.h"
#include "ncp_link.h"
#include "ncp_netif.h"
#include "spinel.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/icmp.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>

LOG_MODULE_REGISTER(nat64, LOG_LEVEL_INF);

/* Protocol numbers. */
#define IPPROTO_ICMPV6  58
#define IPPROTO_UDP_    17
#define IPPROTO_TCP_    6
#define NAT64_MAX_UDP_SESSIONS  8

#define ICMP6_ECHO_REQUEST  128
#define ICMP6_ECHO_REPLY    129
#define ICMP4_ECHO_REQUEST  8
#define ICMP4_ECHO_REPLY    0

/* NAT64 well-known prefix: 64:ff9b::/96 — matches first 12 bytes. */
static const uint8_t nat64_prefix[12] = {
	0x00, 0x64, 0xff, 0x9b, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

bool nat64_is_wellknown(const uint8_t addr6[16])
{
	return memcmp(addr6, nat64_prefix, 12) == 0;
}

/* --------- Session table --------- */

struct nat64_session {
	uint8_t  v6_src[16];      /* original IPv6 src */
	uint8_t  v4_dst[4];       /* external IPv4 dst */
	uint16_t v6_src_port;     /* ICMP id or UDP src port (v6 side) */
	uint16_t v4_src_port;     /* mapped ICMP id / UDP src port (v4 side) */
	uint16_t v4_dst_port;     /* external UDP dst port (UDP sessions) */
	uint8_t  v6_proto;        /* 58 ICMPv6, 17 UDP */
	int      udp_fd;          /* >=0 for UDP sessions; -1 for ICMP */
	int64_t  last_activity;
	int64_t  last_tx_at;      /* uptime ms when we last sent a request */
	bool     in_use;
};

static struct nat64_session sess[NAT64_MAX_SESSIONS];
static struct k_mutex       sess_lock;
static uint16_t             port_cursor = 40000;

static struct nat64_stats   stats;
static struct k_mutex       stats_lock;

static struct net_icmp_ctx  icmp_ctx;
static bool                 icmp_ready;

/* Lookup key: v6_src + v4_dst + proto + (v6_src_port | v4_dst_port). */
static struct nat64_session *find_or_alloc(const uint8_t *v6_src,
					   const uint8_t *v4_dst,
					   uint8_t proto,
					   uint16_t v6_src_port,
					   uint16_t v4_dst_port)
{
	int64_t now = k_uptime_get();
	k_mutex_lock(&sess_lock, K_FOREVER);

	struct nat64_session *victim = NULL;

	for (int i = 0; i < NAT64_MAX_SESSIONS; i++) {
		struct nat64_session *s = &sess[i];
		if (s->in_use &&
		    s->v6_proto == proto &&
		    s->v6_src_port == v6_src_port &&
		    (proto != IPPROTO_UDP_ || s->v4_dst_port == v4_dst_port) &&
		    memcmp(s->v6_src, v6_src, 16) == 0 &&
		    memcmp(s->v4_dst, v4_dst, 4) == 0) {
			s->last_activity = now;
			k_mutex_unlock(&sess_lock);
			return s;
		}
		if (!s->in_use && victim == NULL) {
			victim = s;
		}
	}
	if (!victim) {
		for (int i = 0; i < NAT64_MAX_SESSIONS; i++) {
			if (sess[i].in_use && now - sess[i].last_activity > 120000) {
				victim = &sess[i];
				break;
			}
		}
	}
	if (!victim) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.sessions_full++;
		k_mutex_unlock(&stats_lock);
		k_mutex_unlock(&sess_lock);
		return NULL;
	}

	/* If we're recycling a slot that had a UDP fd, close it. */
	if (victim->udp_fd >= 0) {
		zsock_close(victim->udp_fd);
		victim->udp_fd = -1;
	}

	memcpy(victim->v6_src, v6_src, 16);
	memcpy(victim->v4_dst, v4_dst, 4);
	victim->v6_proto = proto;
	victim->v6_src_port = v6_src_port;
	victim->v4_dst_port = v4_dst_port;
	victim->v4_src_port = port_cursor++;
	if (port_cursor >= 60000) port_cursor = 40000;
	victim->last_activity = now;
	victim->in_use = true;

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.sessions_active++;
	k_mutex_unlock(&stats_lock);
	k_mutex_unlock(&sess_lock);
	return victim;
}

static struct nat64_session *find_by_reply(const uint8_t *peer_v4,
					   uint16_t mapped_id)
{
	ARG_UNUSED(peer_v4);
	/* Lookup by ICMP id only: our mapped_ids come from a cursor and
	 * are globally unique across active sessions.  The peer_v4 on an
	 * ICMP reply may not match the session dst (e.g. router / NAT
	 * rewrite, ICMP from intermediate hops). */
	k_mutex_lock(&sess_lock, K_FOREVER);
	for (int i = 0; i < NAT64_MAX_SESSIONS; i++) {
		struct nat64_session *s = &sess[i];
		if (s->in_use &&
		    s->v6_proto == IPPROTO_ICMPV6 &&
		    s->v4_src_port == mapped_id) {
			s->last_activity = k_uptime_get();
			k_mutex_unlock(&sess_lock);
			return s;
		}
	}
	k_mutex_unlock(&sess_lock);
	return NULL;
}

/* --------- Checksum --------- */

static uint16_t csum16(const uint8_t *buf, size_t len, uint32_t initial)
{
	uint32_t acc = initial;
	for (size_t i = 0; i + 1 < len; i += 2) {
		acc += ((uint16_t)buf[i] << 8) | buf[i + 1];
	}
	if (len & 1) {
		acc += (uint16_t)buf[len - 1] << 8;
	}
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}
	return (uint16_t)(~acc & 0xffff);
}

/* --------- Reply handler: IPv4 Echo Reply -> IPv6 Echo Reply via Spinel --- */

static int send_ipv6_echo_reply(struct nat64_session *s,
				const uint8_t *peer_v4,
				const uint8_t *icmp4_body, size_t body_len,
				uint16_t seq)
{
	/* Build STREAM_NET payload: 2B len + IPv6(40) + ICMPv6(8+body). */
	size_t icmp6_len = 8 + body_len;
	size_t pkt_len   = 40 + icmp6_len;
	if (2 + pkt_len > 1500) return -EMSGSIZE;

	uint8_t buf[1500];
	buf[0] = (uint8_t)(pkt_len & 0xff);
	buf[1] = (uint8_t)(pkt_len >> 8);

	uint8_t *ip6 = buf + 2;
	ip6[0] = 0x60;
	ip6[1] = ip6[2] = ip6[3] = 0;
	ip6[4] = (uint8_t)(icmp6_len >> 8);
	ip6[5] = (uint8_t)(icmp6_len & 0xff);
	ip6[6] = IPPROTO_ICMPV6;
	ip6[7] = 64;
	memcpy(ip6 + 8, nat64_prefix, 12);
	memcpy(ip6 + 20, peer_v4, 4);
	memcpy(ip6 + 24, s->v6_src, 16);

	uint8_t *icmp6 = ip6 + 40;
	icmp6[0] = ICMP6_ECHO_REPLY;
	icmp6[1] = 0;
	icmp6[2] = icmp6[3] = 0;
	icmp6[4] = (uint8_t)(s->v6_src_port >> 8);
	icmp6[5] = (uint8_t)(s->v6_src_port & 0xff);
	icmp6[6] = (uint8_t)(seq >> 8);
	icmp6[7] = (uint8_t)(seq & 0xff);
	memcpy(icmp6 + 8, icmp4_body, body_len);

	/* ICMPv6 pseudo-header + message. */
	uint32_t acc = 0;
	for (int i = 0; i < 32; i += 2) {
		acc += ((uint16_t)(ip6 + 8)[i] << 8) | (ip6 + 8)[i + 1];
	}
	acc += icmp6_len;
	acc += IPPROTO_ICMPV6;
	uint16_t ccs = csum16(icmp6, icmp6_len, acc);
	icmp6[2] = (ccs >> 8) & 0xff;
	icmp6[3] = ccs & 0xff;

	uint32_t ls = 0;
	int rv = ncp_link_set_raw(SPINEL_PROP_STREAM_NET, buf, 2 + pkt_len,
				  &ls, K_MSEC(500));
	if (rv < 0) {
		LOG_WRN("STREAM_NET reply send rv=%d ls=%u", rv, ls);
	}
	return rv;
}

static enum net_verdict on_icmp_reply(struct net_icmp_ctx *ctx,
				      struct net_pkt *pkt,
				      struct net_icmp_ip_hdr *ip_hdr,
				      struct net_icmp_hdr *icmp_hdr,
				      void *user_data)
{
	ARG_UNUSED(ctx); ARG_UNUSED(user_data);

	uint8_t peer_v4[4];
	memcpy(peer_v4, ip_hdr->ipv4->src, 4);

	/* Cursor is at the ICMP id/seq fields after the 4-byte generic
	 * ICMP header that Zephyr's net_icmp consumed. */
	uint16_t ident = 0, seq = 0;
	if (net_pkt_read_be16(pkt, &ident) < 0) return NET_DROP;
	if (net_pkt_read_be16(pkt, &seq)   < 0) return NET_DROP;

	uint8_t body[1500];
	size_t body_len = net_pkt_remaining_data(pkt);
	if (body_len > sizeof(body)) body_len = sizeof(body);
	if (body_len > 0) {
		if (net_pkt_read(pkt, body, body_len) < 0) return NET_DROP;
	}

	struct nat64_session *s = find_by_reply(peer_v4, ident);
	if (!s) {
		return NET_DROP;
	}
	(void)send_ipv6_echo_reply(s, peer_v4, body, body_len, seq);
	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.rx_pkts++;
	k_mutex_unlock(&stats_lock);
	return NET_OK;
}

/* --------- UDP reply synthesis: v4 UDP reply -> v6 UDP via STREAM_NET --- */

static int send_ipv6_udp_reply(struct nat64_session *s,
			       const uint8_t *peer_v4,
			       uint16_t peer_port,
			       const uint8_t *udp_payload, size_t udp_len)
{
	/* STREAM_NET payload = 2B len + IPv6 header(40) + UDP header(8) + payload. */
	size_t udp_total = 8 + udp_len;
	size_t pkt_len = 40 + udp_total;
	if (2 + pkt_len > 1500) return -EMSGSIZE;

	uint8_t buf[1500];
	buf[0] = (uint8_t)(pkt_len & 0xff);
	buf[1] = (uint8_t)(pkt_len >> 8);

	uint8_t *ip6 = buf + 2;
	ip6[0] = 0x60;
	ip6[1] = ip6[2] = ip6[3] = 0;
	ip6[4] = (uint8_t)(udp_total >> 8);
	ip6[5] = (uint8_t)(udp_total & 0xff);
	ip6[6] = IPPROTO_UDP_;
	ip6[7] = 64;
	memcpy(ip6 + 8, nat64_prefix, 12);
	memcpy(ip6 + 20, peer_v4, 4);
	memcpy(ip6 + 24, s->v6_src, 16);

	uint8_t *udp = ip6 + 40;
	udp[0] = (uint8_t)(peer_port >> 8);       /* src port = peer's */
	udp[1] = (uint8_t)(peer_port & 0xff);
	udp[2] = (uint8_t)(s->v6_src_port >> 8);  /* dst port = sensor's orig */
	udp[3] = (uint8_t)(s->v6_src_port & 0xff);
	udp[4] = (uint8_t)(udp_total >> 8);
	udp[5] = (uint8_t)(udp_total & 0xff);
	udp[6] = udp[7] = 0;                      /* checksum, filled below */
	memcpy(udp + 8, udp_payload, udp_len);

	/* IPv6 UDP checksum: pseudo-header + UDP header + payload. */
	uint32_t acc = 0;
	for (int i = 0; i < 32; i += 2) {
		acc += ((uint16_t)(ip6 + 8)[i] << 8) | (ip6 + 8)[i + 1];
	}
	acc += udp_total;
	acc += IPPROTO_UDP_;
	uint16_t ccs = csum16(udp, udp_total, acc);
	if (ccs == 0) ccs = 0xffff;  /* UDPv6 rule: 0 -> 0xffff */
	udp[6] = (ccs >> 8) & 0xff;
	udp[7] = ccs & 0xff;

	uint32_t ls = 0;
	int rv = ncp_link_set_raw(SPINEL_PROP_STREAM_NET, buf, 2 + pkt_len,
				  &ls, K_MSEC(2000));
	if (rv < 0) {
		LOG_WRN("UDP reply STREAM_NET rv=%d ls=%u", rv, ls);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.rx_drops++;
		k_mutex_unlock(&stats_lock);
	}
	return rv;
}

/* --------- UDP RX thread: polls all active UDP sockets -------- */

static K_THREAD_STACK_DEFINE(udp_rx_stack, 4096);
static struct k_thread       udp_rx_thread;

static void udp_rx_thread_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	struct zsock_pollfd pollfds[NAT64_MAX_UDP_SESSIONS];
	struct nat64_session *slots[NAT64_MAX_UDP_SESSIONS];

	while (1) {
		int n = 0;
		int64_t now = k_uptime_get();
		k_mutex_lock(&sess_lock, K_FOREVER);
		for (int i = 0; i < NAT64_MAX_SESSIONS && n < NAT64_MAX_UDP_SESSIONS; i++) {
			if (sess[i].in_use && sess[i].udp_fd >= 0) {
				/* Close sockets only after long idleness (2 min).
				 * The 10 s we had before was dropping NAT64
				 * sessions mid-OTA-download when the sensor's
				 * zsock briefly stalled. */
				if (now - sess[i].last_activity > 120000) {
					zsock_close(sess[i].udp_fd);
					sess[i].udp_fd = -1;
					continue;
				}
				pollfds[n].fd = sess[i].udp_fd;
				pollfds[n].events = ZSOCK_POLLIN;
				pollfds[n].revents = 0;
				slots[n] = &sess[i];
				n++;
			}
		}
		k_mutex_unlock(&sess_lock);

		if (n == 0) {
			k_sleep(K_MSEC(200));
			continue;
		}

		int ready = zsock_poll(pollfds, n, 200);
		if (ready <= 0) continue;

		for (int i = 0; i < n; i++) {
			if (!(pollfds[i].revents & ZSOCK_POLLIN)) continue;
			uint8_t buf[1024];
			struct net_sockaddr_in from;
			socklen_t flen = sizeof(from);
			ssize_t r = zsock_recvfrom(pollfds[i].fd, buf, sizeof(buf),
						   0, (struct net_sockaddr *)&from,
						   &flen);
			if (r <= 0) continue;
			int64_t t_rx = k_uptime_get();
			uint8_t peer_v4[4];
			memcpy(peer_v4, &from.sin_addr, 4);
			uint16_t peer_port = ntohs(from.sin_port);
			int64_t hub_rtt = slots[i]->last_tx_at > 0
				? t_rx - slots[i]->last_tx_at : -1;
			LOG_INF("rx v4->v6 udp len=%zd <- %u.%u.%u.%u:%u "
				"(src_port=%u, hub_rtt=%lld ms)",
				r, peer_v4[0], peer_v4[1], peer_v4[2], peer_v4[3],
				peer_port, slots[i]->v6_src_port, hub_rtt);
			int64_t t_send_v6 = k_uptime_get();
			(void)send_ipv6_udp_reply(slots[i], peer_v4, peer_port,
						  buf, (size_t)r);
			LOG_INF("rx fwd-to-ncp took %lld ms",
				k_uptime_get() - t_send_v6);
			k_mutex_lock(&stats_lock, K_FOREVER);
			stats.rx_pkts++;
			k_mutex_unlock(&stats_lock);
		}
	}
}

/* --------- UDP outbound TX from IPv6 --------- */

static int nat64_tx_v6_udp(const uint8_t *src6, const uint8_t *v4_dst_be,
			   const uint8_t *udp_hdr, size_t udp_len)
{
	if (udp_len < 8) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_bad_packet++;
		k_mutex_unlock(&stats_lock);
		return -EINVAL;
	}
	uint16_t src_port = ((uint16_t)udp_hdr[0] << 8) | udp_hdr[1];
	uint16_t dst_port = ((uint16_t)udp_hdr[2] << 8) | udp_hdr[3];
	const uint8_t *payload = udp_hdr + 8;
	size_t         plen    = udp_len - 8;

	struct nat64_session *s = find_or_alloc(src6, v4_dst_be, IPPROTO_UDP_,
						src_port, dst_port);
	if (!s) return -ENOMEM;

	if (s->udp_fd < 0) {
		s->udp_fd = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM,
					 NET_IPPROTO_UDP);
		if (s->udp_fd < 0) {
			LOG_WRN("udp socket() errno=%d", errno);
			k_mutex_lock(&stats_lock, K_FOREVER);
			stats.tx_no_wifi++;
			k_mutex_unlock(&stats_lock);
			return -ENETDOWN;
		}
	}

	struct net_sockaddr_in dst = {
		.sin_family = NET_AF_INET,
		.sin_port   = htons(dst_port),
	};
	memcpy(&dst.sin_addr, v4_dst_be, 4);

	s->last_tx_at = k_uptime_get();
	ssize_t n = zsock_sendto(s->udp_fd, payload, plen, 0,
				 (struct net_sockaddr *)&dst, sizeof(dst));
	if (n < 0) {
		LOG_WRN("udp sendto -> %u.%u.%u.%u:%u errno=%d",
			v4_dst_be[0], v4_dst_be[1], v4_dst_be[2], v4_dst_be[3],
			dst_port, errno);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_no_wifi++;
		k_mutex_unlock(&stats_lock);
		return -EIO;
	}

	LOG_INF("tx v6->v4 udp len=%zu -> %u.%u.%u.%u:%u (src_port=%u)",
		plen,
		v4_dst_be[0], v4_dst_be[1], v4_dst_be[2], v4_dst_be[3],
		dst_port, src_port);

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_pkts++;
	stats.tx_udp++;
	k_mutex_unlock(&stats_lock);
	return 0;
}

/* --------- IPv6 -> IPv4 translation (outbound) --------- */

int nat64_tx_v6(const uint8_t *ipv6, size_t len)
{
	if (len < 40) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_bad_packet++;
		k_mutex_unlock(&stats_lock);
		return -EINVAL;
	}
	const uint8_t *src6 = ipv6 + 8;
	const uint8_t *dst6 = ipv6 + 24;
	uint8_t next_hdr    = ipv6[6];
	uint16_t payload_len = ((uint16_t)ipv6[4] << 8) | ipv6[5];
	const uint8_t *payload = ipv6 + 40;

	if (!nat64_is_wellknown(dst6)) {
		return -ENOENT;
	}

	/* Dispatch on proto. */
	const uint8_t *v4_dst_be_top = dst6 + 12;
	if (next_hdr == IPPROTO_UDP_) {
		return nat64_tx_v6_udp(src6, v4_dst_be_top, payload, payload_len);
	}
	if (next_hdr != IPPROTO_ICMPV6) {
		LOG_WRN("tx: unsupported next_hdr=%u", next_hdr);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_bad_packet++;
		k_mutex_unlock(&stats_lock);
		return -ENOTSUP;
	}
	if (payload_len < 8 || payload[0] != ICMP6_ECHO_REQUEST) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_bad_packet++;
		k_mutex_unlock(&stats_lock);
		return -ENOTSUP;
	}

	const uint8_t *v4_dst_be = dst6 + 12;
	uint16_t sport = ((uint16_t)payload[4] << 8) | payload[5];
	uint16_t seq   = ((uint16_t)payload[6] << 8) | payload[7];

	struct nat64_session *s = find_or_alloc(src6, v4_dst_be, next_hdr,
						sport, 0);
	if (!s) {
		return -ENOMEM;
	}

	if (!icmp_ready) {
		LOG_WRN("tx drop: ICMP ctx not ready");
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_no_wifi++;
		k_mutex_unlock(&stats_lock);
		return -ENETDOWN;
	}

	struct net_sockaddr_in dst = {
		.sin_family = NET_AF_INET,
	};
	memcpy(&dst.sin_addr, v4_dst_be, 4);

	/* Pass-through the echo payload (after the 8-byte ICMPv6 header). */
	const uint8_t *echo_data = payload + 8;
	size_t echo_data_len = payload_len - 8;

	struct net_icmp_ping_params params = {
		.identifier = s->v4_src_port,
		.sequence   = seq,
		.tc_tos     = 0,
		.priority   = -1,
		.data       = (uint8_t *)echo_data,
		.data_size  = echo_data_len,
	};

	int rv = net_icmp_send_echo_request_no_wait(&icmp_ctx, NULL,
						    (struct net_sockaddr *)&dst,
						    &params, NULL);
	if (rv < 0) {
		LOG_WRN("send_echo_request rv=%d -> %u.%u.%u.%u",
			rv, v4_dst_be[0], v4_dst_be[1], v4_dst_be[2], v4_dst_be[3]);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_no_wifi++;
		k_mutex_unlock(&stats_lock);
		return rv;
	}

	LOG_INF("tx v6->v4 icmp -> %u.%u.%u.%u id=%u(%u) seq=%u",
		v4_dst_be[0], v4_dst_be[1], v4_dst_be[2], v4_dst_be[3],
		sport, s->v4_src_port, seq);

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_pkts++;
	stats.tx_icmp6++;
	k_mutex_unlock(&stats_lock);
	return 0;
}

int nat64_rx_v4(const uint8_t *ipv4, size_t len)
{
	ARG_UNUSED(ipv4); ARG_UNUSED(len);
	return -ENOSYS;  /* handled via on_icmp_reply callback */
}

/* --------- Init --------- */

int nat64_init(void)
{
	k_mutex_init(&sess_lock);
	k_mutex_init(&stats_lock);
	for (int i = 0; i < NAT64_MAX_SESSIONS; i++) {
		sess[i].udp_fd = -1;
	}

	int rv = net_icmp_init_ctx(&icmp_ctx, NET_AF_INET,
				   NET_ICMPV4_ECHO_REPLY, 0, on_icmp_reply);
	if (rv < 0) {
		LOG_ERR("net_icmp_init_ctx: %d", rv);
		return rv;
	}
	icmp_ready = true;

	k_thread_create(&udp_rx_thread, udp_rx_stack,
			K_THREAD_STACK_SIZEOF(udp_rx_stack),
			udp_rx_thread_fn, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&udp_rx_thread, "nat64_udp_rx");

	LOG_INF("NAT64 ready (ICMPv4 + UDP)");
	return 0;
}

void nat64_stats_get(struct nat64_stats *out)
{
	k_mutex_lock(&stats_lock, K_FOREVER);
	*out = stats;
	k_mutex_unlock(&stats_lock);
}
