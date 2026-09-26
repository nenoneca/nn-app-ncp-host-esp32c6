/* SPDX-License-Identifier: Apache-2.0 */

#include "border_agent.h"
#include "ncp_link.h"
#include "ncp_netif.h"
#include "spinel.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>

#include <nn_osal/osal.h>

NN_OSAL_LOG_MODULE(border_agent);

/* IPv4-mapped IPv6 prefix: ::ffff:0:0/96 */
static const uint8_t v4mapped_prefix[12] = {
	0,0,0,0, 0,0,0,0, 0,0,0xff,0xff,
};

/* NAT64 well-known prefix used for IPv4-as-IPv6 source address when
 * tunneling commissioner traffic via STREAM_NET. */
static const uint8_t nat64_prefix[12] = {
	0x00,0x64, 0xff,0x9b, 0,0,0,0, 0,0,0,0,
};

/* IP6 next-header for UDP. */
#define IPPROTO_UDP_ 17

/* Active commissioner session table. */
struct comm_session_decl {
	bool     in_use;
	uint8_t  v4[4];
	uint16_t port;
	int64_t  last_seen;
};
#define COMM_SESSION_MAX 8
static struct comm_session_decl comm_sessions[COMM_SESSION_MAX];
static struct k_mutex            comm_sessions_lock;

/* BR socket + stats. */
static int                       udp_sock = -1;
static struct k_mutex            stats_lock;
static struct border_agent_stats stats;

/* Internet checksum over a buffer with running accumulator. */
static uint16_t bba_csum16(const uint8_t *buf, size_t len, uint32_t acc)
{
	for (size_t i = 0; i + 1 < len; i += 2) {
		acc += ((uint16_t)buf[i] << 8) | buf[i + 1];
	}
	if (len & 1) {
		acc += (uint16_t)buf[len - 1] << 8;
	}
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}
	return (uint16_t)~acc;
}

/* Find an NCP mesh-local-EID-shaped IPv6 address mirrored on our iface
 * (ML prefix, but not the RLOC-shaped `:0:00ff:fe00:XXXX` IID).  This
 * is the dst we use for the STREAM_NET commissioner-tunnel: it's a
 * NCP-owned address (so DetermineAction fires aReceive=true), and our
 * patched source-check in ip6.cpp allows the IPv4-mapped commissioner
 * source through when dst is one of our own unicast addresses. */
static int find_ncp_ml_eid(uint8_t out[16])
{
	struct net_if *iface = ncp_netif_get();
	if (!iface || !iface->config.ip.ipv6) return -ENODEV;
	uint8_t ml[20]; size_t mllen = sizeof(ml);
	if (ncp_link_get(SPINEL_PROP_IPV6_ML_PREFIX, ml, &mllen, K_MSEC(500))
	    < 0 || mllen < 16) {
		return -EIO;
	}
	for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		struct net_if_addr *a = &iface->config.ip.ipv6->unicast[i];
		if (!a->is_used) continue;
		const uint8_t *b = a->address.in6_addr.s6_addr;
		if (memcmp(b, ml, 8) != 0) continue;       /* prefix match */
		/* Skip RLOC-shaped addresses (XXXX:0:00ff:fe00:XXXX). */
		if (b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0xff &&
		    b[12]==0xfe && b[13]==0) continue;
		memcpy(out, b, 16);
		return 0;
	}
	return -ENOENT;
}

/* Send a commissioner-originated UDP payload to the NCP's BA via
 * STREAM_NET (a synthesized raw IPv6 packet) instead of UDP_FORWARD.
 *
 * UDP_FORWARD wraps the payload as SPINEL_PROP_THREAD_UDP_FORWARD_STREAM
 * and the OT NCP delivers it through `otUdpForwardReceive`, which marks
 * the resulting MessageInfo with `IsHostInterface=true` and an IPv4-
 * mapped peer address.  In our setup BA receives that packet but never
 * replies (verified empirically — internal commissioner over Thread
 * petitions BA fine, the same ClientHello via UDP_FORWARD silently
 * disappears past `Ip6::Udp::HandlePayload`).
 *
 * The STREAM_NET path bypasses that quirk: NCP receives a normal IPv6
 * datagram, the IP6/UDP demux runs as if the packet had arrived from
 * the radio, and BA's DTLS server sees a "regular" peer.  We use the
 * NAT64 well-known prefix to map the IPv4 commissioner into IPv6 so
 * that BA's reply (which OT will route off-mesh) comes back to host
 * via the existing nat64.c rx path. */
/* Record commissioner (v4, port) in the session table so the inbound
 * demux can find it.  Updates last_seen if already present. */
static void comm_session_touch(const uint8_t v4[4], uint16_t port)
{
	int64_t now = nn_osal_uptime_ms();
	int free_slot = -1;
	int oldest = 0;
	int64_t oldest_ts = INT64_MAX;
	k_mutex_lock(&comm_sessions_lock, K_FOREVER);
	for (int i = 0; i < COMM_SESSION_MAX; i++) {
		struct comm_session_decl *s = &comm_sessions[i];
		if (s->in_use && memcmp(s->v4, v4, 4) == 0 && s->port == port) {
			s->last_seen = now;
			k_mutex_unlock(&comm_sessions_lock);
			return;
		}
		if (!s->in_use && free_slot < 0) free_slot = i;
		if (s->in_use && s->last_seen < oldest_ts) {
			oldest_ts = s->last_seen;
			oldest = i;
		}
	}
	int slot = free_slot >= 0 ? free_slot : oldest;
	struct comm_session_decl *s = &comm_sessions[slot];
	s->in_use = true;
	memcpy(s->v4, v4, 4);
	s->port = port;
	s->last_seen = now;
	k_mutex_unlock(&comm_sessions_lock);
}

bool border_agent_demux_inbound(const uint8_t v4_dst[4], uint16_t udp_dst_port,
				const uint8_t *udp_payload, size_t udp_payload_len)
{
	bool match = false;
	k_mutex_lock(&comm_sessions_lock, K_FOREVER);
	for (int i = 0; i < COMM_SESSION_MAX; i++) {
		struct comm_session_decl *s = &comm_sessions[i];
		if (!s->in_use) continue;
		if (memcmp(s->v4, v4_dst, 4) == 0 && s->port == udp_dst_port) {
			match = true;
			s->last_seen = nn_osal_uptime_ms();
			break;
		}
	}
	k_mutex_unlock(&comm_sessions_lock);
	if (!match) return false;

	if (udp_sock < 0) return true;
	struct net_sockaddr_in to = {
		.sin_family = NET_AF_INET,
		.sin_port   = htons(udp_dst_port),
	};
	memcpy(&to.sin_addr, v4_dst, 4);
	ssize_t sent = zsock_sendto(udp_sock, udp_payload, udp_payload_len, 0,
				    (struct net_sockaddr *)&to, sizeof(to));
	if (sent < 0) {
		NN_LOG_WRN("ba demux sendto: %d", errno);
	}
	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_to_commissioner++;
	k_mutex_unlock(&stats_lock);
	return true;
}

int border_agent_try_stream_net_tx(const uint8_t *payload, size_t payload_len,
				   uint16_t commissioner_port,
				   const uint8_t commissioner_v4[4])
{
	if (payload_len + 40 + 8 + 2 > 1500) return -EMSGSIZE;

	/* Track this session so we can demux the reply back to the
	 * commissioner when NCP's BA replies via STREAM_NET. */
	comm_session_touch(commissioner_v4, commissioner_port);

	uint8_t ml_eid[16];
	int rv = find_ncp_ml_eid(ml_eid);
	if (rv < 0) return rv;

	size_t udp_total = 8 + payload_len;
	size_t pkt_len   = 40 + udp_total;
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
	memcpy(ip6 + 8,  nat64_prefix, 12);          /* src = 64:ff9b::comm_v4 */
	memcpy(ip6 + 20, commissioner_v4, 4);
	memcpy(ip6 + 24, ml_eid, 16);                /* dst = NCP ML-EID */

	uint8_t *udp = ip6 + 40;
	udp[0] = (uint8_t)(commissioner_port >> 8);  /* src port (commissioner) */
	udp[1] = (uint8_t)(commissioner_port & 0xff);
	udp[2] = 0xc0;                               /* dst port = 49191 = 0xc027 */
	udp[3] = 0x27;
	udp[4] = (uint8_t)(udp_total >> 8);
	udp[5] = (uint8_t)(udp_total & 0xff);
	udp[6] = udp[7] = 0;                         /* checksum, computed below */
	memcpy(udp + 8, payload, payload_len);

	/* IPv6 UDP checksum with pseudo-header. */
	uint32_t acc = 0;
	for (int i = 0; i < 32; i += 2) {
		acc += ((uint16_t)(ip6 + 8)[i] << 8) | (ip6 + 8)[i + 1];
	}
	acc += udp_total;
	acc += IPPROTO_UDP_;
	uint16_t ccs = bba_csum16(udp, udp_total, acc);
	if (ccs == 0) ccs = 0xffff;
	udp[6] = (ccs >> 8) & 0xff;
	udp[7] = ccs & 0xff;

	uint32_t ls = 0;
	int srv = ncp_link_set_raw(SPINEL_PROP_STREAM_NET, buf, 2 + pkt_len,
				   &ls, K_MSEC(2000));
	if (srv < 0) {
		NN_LOG_WRN("ba stream_net tx rv=%d ls=%u", srv, ls);
	}
	return srv;
}

/* (forward decls are at top of file; this is the actual init.) */

static K_THREAD_STACK_DEFINE(rx_stack, 4096);
static struct k_thread        rx_thread;

/* --- NCP -> commissioner: called from Spinel RX thread via ncp_link. */
static void from_ncp_cb(const uint8_t *payload, size_t len,
			uint16_t remote_port,
			const uint8_t remote_ip6[16],
			uint16_t local_port)
{
	ARG_UNUSED(local_port);
	if (udp_sock < 0) {
		k_mutex_lock(&stats_lock, K_FOREVER); stats.drops++;
		k_mutex_unlock(&stats_lock);
		return;
	}

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.rx_from_ncp++;
	k_mutex_unlock(&stats_lock);

	/* remote_ip6 is the commissioner address.  For IPv4 peers it's
	 * wrapped as ::ffff:a.b.c.d — unpack. */
	struct net_sockaddr_storage to;
	socklen_t tolen;
	if (memcmp(remote_ip6, v4mapped_prefix, 12) == 0) {
		struct net_sockaddr_in *v4 = (struct net_sockaddr_in *)&to;
		v4->sin_family = NET_AF_INET;
		v4->sin_port   = htons(remote_port);
		memcpy(&v4->sin_addr, remote_ip6 + 12, 4);
		tolen = sizeof(*v4);
	} else {
		struct net_sockaddr_in6 *v6 = (struct net_sockaddr_in6 *)&to;
		v6->sin6_family = NET_AF_INET6;
		v6->sin6_port   = htons(remote_port);
		memcpy(&v6->sin6_addr, remote_ip6, 16);
		tolen = sizeof(*v6);
	}

	ssize_t sent = zsock_sendto(udp_sock, payload, len, 0,
				    (struct net_sockaddr *)&to, tolen);
	if (sent < 0) {
		NN_LOG_WRN("sendto commissioner failed: %d", errno);
		k_mutex_lock(&stats_lock, K_FOREVER); stats.drops++;
		k_mutex_unlock(&stats_lock);
		return;
	}
	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_to_commissioner++;
	k_mutex_unlock(&stats_lock);
}

/* --- Commissioner -> NCP: recv loop thread. */
static void rx_thread_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	while (1) {
		if (udp_sock < 0) {
			/* Lazy open: wait for wlan0 to be up. */
			udp_sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM,
						NET_IPPROTO_UDP);
			if (udp_sock < 0) {
				k_sleep(K_SECONDS(1));
				continue;
			}
			struct net_sockaddr_in bind_addr = {
				.sin_family = NET_AF_INET,
				.sin_port   = htons(BORDER_AGENT_PORT),
				.sin_addr   = { .s_addr = 0 },  /* ANY */
			};
			if (zsock_bind(udp_sock,
				       (struct net_sockaddr *)&bind_addr,
				       sizeof(bind_addr)) < 0) {
				NN_LOG_ERR("bind :%d failed: %d",
					BORDER_AGENT_PORT, errno);
				zsock_close(udp_sock);
				udp_sock = -1;
				k_sleep(K_SECONDS(2));
				continue;
			}
			NN_LOG_INF("UDP :%d listener up", BORDER_AGENT_PORT);
		}

		uint8_t buf[1024];
		struct net_sockaddr_storage from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = zsock_recvfrom(udp_sock, buf, sizeof(buf), 0,
					   (struct net_sockaddr *)&from,
					   &fromlen);
		if (n <= 0) {
			if (errno == EAGAIN) continue;
			NN_LOG_WRN("recvfrom: %d", errno);
			nn_osal_sleep_ms(100);
			continue;
		}
		if (IS_ENABLED(CONFIG_BORDER_AGENT_LOG_RX)) {
			printk("ba: rx %zd B from family=%u\n", n,
			       (unsigned)from.ss_family);
		}

		uint16_t remote_port = 0;
		uint8_t  remote_ip6[16] = {0};
		if (from.ss_family == NET_AF_INET) {
			struct net_sockaddr_in *v4 = (void *)&from;
			remote_port = ntohs(v4->sin_port);
			memcpy(remote_ip6, v4mapped_prefix, 12);
			memcpy(remote_ip6 + 12, &v4->sin_addr, 4);
		} else if (from.ss_family == NET_AF_INET6) {
			struct net_sockaddr_in6 *v6 = (void *)&from;
			remote_port = ntohs(v6->sin6_port);
			memcpy(remote_ip6, &v6->sin6_addr, 16);
		} else {
			continue;
		}

		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.rx_from_commissioner++;
		k_mutex_unlock(&stats_lock);

		/* DIAG: send the same packet via STREAM_NET as a synthesized
		 * IPv6 UDP datagram so we can observe whether NCP's BA replies
		 * via that path (UDP_FORWARD path silently drops). */
		if (memcmp(remote_ip6, v4mapped_prefix, 12) == 0) {
			int srv = border_agent_try_stream_net_tx(
				buf, (size_t)n, remote_port, remote_ip6 + 12);
			if (srv == 0) {
				printk("ba: stream_net tx OK\n");
			}
		}

		int rv = ncp_link_udp_forward_tx(buf, (size_t)n,
						 remote_port, remote_ip6,
						 BORDER_AGENT_PORT);
		if (rv < 0) {
			NN_LOG_WRN("udp_forward_tx rv=%d", rv);
			k_mutex_lock(&stats_lock, K_FOREVER);
			stats.drops++;
			k_mutex_unlock(&stats_lock);
		} else {
			k_mutex_lock(&stats_lock, K_FOREVER);
			stats.tx_to_ncp++;
			k_mutex_unlock(&stats_lock);
		}
	}
}

int border_agent_init(void)
{
	k_mutex_init(&stats_lock);
	k_mutex_init(&comm_sessions_lock);
	ncp_link_set_udp_fwd_cb(from_ncp_cb);
	k_thread_create(&rx_thread, rx_stack, K_THREAD_STACK_SIZEOF(rx_stack),
			rx_thread_fn, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&rx_thread, "ba_rx");
	return 0;
}

void border_agent_stats_get(struct border_agent_stats *out)
{
	k_mutex_lock(&stats_lock, K_FOREVER);
	*out = stats;
	k_mutex_unlock(&stats_lock);
}
