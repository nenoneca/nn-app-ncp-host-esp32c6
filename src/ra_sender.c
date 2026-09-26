/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ra_sender.c — periodic IPv6 Router Advertisement (RFC 4861 + RFC 4191)
 *                emitter on the WiFi netif.
 *
 * Why: this NCP-host plays Thread Border Router.  Sensors on the Thread
 * mesh sit behind the prefix `<mesh-local>/64` (and any on-mesh prefix
 * the leader publishes).  Hosts on the WiFi/LAN side can only initiate
 * traffic to those sensors if they have a route — and in a properly
 * deployed BR that route comes from a Router Advertisement carrying a
 * Route Information Option (RFC 4191 §2.3, ND option type 24).
 *
 * Zephyr's IPv6 ND code only RECEIVES RAs; it has no native sender.  This
 * module fills that gap.  We construct ICMPv6 type 134 packets with:
 *   - Source Link-Layer Address option (type 1, our WiFi MAC)
 *   - One Route Information option per known Thread prefix (type 24, /64,
 *     medium preference, 30-min lifetime, refreshed every 30s)
 *
 * Sent to ff02::1 (all-nodes mcast) on the WiFi netif at boot, every 30s
 * thereafter, and on demand via ra_sender_kick() (called from
 * ncp_netif_sync_routes when prefixes change).
 *
 * One-time Linux side config to accept /64 RIOs:
 *   sudo sysctl -w net.ipv6.conf.<iface>.accept_ra_rt_info_max_plen=64
 */

#include "ra_sender.h"

#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
/* <zephyr/net/wifi_mgmt.h> not needed — only net_if_get_first_wifi()
 * is used (declared in net_if.h above). */

#include <string.h>

#include <nn_osal/osal.h>

/* Pull in Zephyr-internal ICMPv6 helpers (not part of public headers but
 * widely used by other Zephyr networking code).  Same path used by
 * subsys/net/ip/ipv6_nbr.c. */
extern int net_ipv6_create(struct net_pkt *pkt, const struct net_in6_addr *src,
			   const struct net_in6_addr *dst);
extern int net_icmpv6_create(struct net_pkt *pkt, uint8_t icmp_type, uint8_t icmp_code);
extern int net_ipv6_finalize(struct net_pkt *pkt, uint8_t next_header_proto);
extern int net_send_data(struct net_pkt *pkt);

NN_OSAL_LOG_MODULE(ra_sender);

#define RA_INTERVAL_S          30
#define RA_ROUTER_LIFETIME_S   0      /* not a default router; only RIOs */
#define RA_RIO_LIFETIME_S      1800   /* 30 min — > interval so no flap */
#define RA_HOP_LIMIT           64
#define RA_FLAGS               0      /* M=0, O=0, no managed/other config */
#define ND_HOP_LIMIT           255    /* mandatory for ND messages */

/* All-nodes multicast — RA destination per RFC 4861 §6.2.4 */
static const struct net_in6_addr ALL_NODES_MCAST = {
	{ { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01 } }
};

static struct k_work_delayable ra_work;
static bool s_started;

/* Look up the WiFi netif (uses net_if_get_first_wifi(), same as
 * auto_wifi_connect() in main.c). */
static struct net_if *get_wifi_iface(void)
{
	return net_if_get_first_wifi();
}

/* Append an option to the RA payload buffer.  Each option's length field
 * is in 8-byte units (RFC 4861 §4.6).  Returns new write offset, or -1 on
 * overflow. */
static int append_opt(uint8_t *buf, size_t cap, int off,
		      uint8_t type, uint8_t len_units,
		      const void *body, size_t body_len)
{
	size_t total = (size_t)len_units * 8;
	if (total < 2 + body_len || off + (int)total > (int)cap) {
		return -1;
	}
	buf[off + 0] = type;
	buf[off + 1] = len_units;
	memcpy(&buf[off + 2], body, body_len);
	if (total > 2 + body_len) {
		memset(&buf[off + 2 + body_len], 0, total - 2 - body_len);
	}
	return off + (int)total;
}

/* Build the RA payload (everything after the ICMPv6 type/code/checksum
 * fields): RA fixed header + options.  Returns total payload size.
 *
 * For each on-mesh Thread prefix we emit BOTH:
 *   - RIO (RFC 4191 type 24): tells LAN hosts "route via me to reach this
 *     prefix" — installed in their kernel route table.
 *   - PIO (RFC 4861 type 3, A=1, L=0): tells LAN hosts "auto-configure an
 *     IPv6 address in this prefix on yourself" via SLAAC.  This is what
 *     gives the hub a global IPv6 source addr so it can initiate
 *     hub→sensor traffic with a routable src.
 *
 * Mesh-local (the FIRST prefix in the netif's array, which sync_routes
 * always adds first from SPINEL_PROP_IPV6_ML_PREFIX) gets RIO only — no
 * PIO — so LAN hosts don't try to SLAAC mesh-local-flavoured addresses
 * that would only confuse Thread's own ND. */
static int build_ra_payload(struct net_if *wifi,
			    uint8_t *buf, size_t cap,
			    int *prefix_count_out)
{
	int off = 0;
	int prefix_count = 0;

	/* RA fixed header */
	if (off + 12 > (int)cap) return -1;
	buf[off++] = RA_HOP_LIMIT;          /* cur hop limit */
	buf[off++] = RA_FLAGS;              /* M/O/Prf flags */
	buf[off++] = (RA_ROUTER_LIFETIME_S >> 8) & 0xff;
	buf[off++] = RA_ROUTER_LIFETIME_S & 0xff;
	memset(&buf[off], 0, 4); off += 4;  /* reachable time = 0 */
	memset(&buf[off], 0, 4); off += 4;  /* retrans timer = 0 */

	/* Source Link-Layer Address option (type 1, len 1 = 8 bytes for
	 * 6-byte MAC + 2-byte hdr).  Required so peers don't have to do an
	 * NS round-trip to resolve us. */
	struct net_linkaddr *ll = net_if_get_link_addr(wifi);
	if (ll && ll->len == 6) {
		off = append_opt(buf, cap, off,
				 1 /* SLLAO */, 1 /* 8 bytes */,
				 ll->addr, 6);
		if (off < 0) return -1;
	}

	/* Walk the Thread netif's prefix list and add one RFC 4191 RIO per
	 * /64 prefix.  We pick the netif that ISN'T the WiFi (i.e., the
	 * `ncp_thread` dummy netif); ncp_netif_sync_routes() populates it. */
	struct net_if *thread_iface = NULL;
	struct net_if *iter = NULL;
	int idx = 0;
	while ((iter = net_if_get_by_index(++idx)) != NULL) {
		if (iter != wifi) {
			thread_iface = iter;
			break;
		}
	}
	if (!thread_iface || !thread_iface->config.ip.ipv6) {
		*prefix_count_out = 0;
		return off;
	}

	struct net_if_ipv6_prefix *prefixes = thread_iface->config.ip.ipv6->prefix;
	bool first_used_emitted = false;  /* track ML (first added by sync_routes) */
	for (int i = 0; i < NET_IF_MAX_IPV6_PREFIX; i++) {
		if (!prefixes[i].is_used) continue;
		uint8_t plen = prefixes[i].len;
		if (plen == 0 || plen > 128) continue;

		bool is_mesh_local = !first_used_emitted;
		first_used_emitted = true;

		/* ── RIO (always, RFC 4191 §2.3) ─────────────────────────
		 * body: prefix_len(1) + flags(1) + lifetime(4) + prefix(8 or 16). */
		{
			uint8_t pfx_bytes = (plen <= 64) ? 8 : 16;
			uint8_t len_units = (pfx_bytes == 8) ? 2 : 3;
			uint8_t body[2 + 4 + 16];
			body[0] = plen;
			body[1] = 0;  /* Prf=00 (medium), reserved bits 0 */
			uint32_t lt = RA_RIO_LIFETIME_S;
			body[2] = (lt >> 24) & 0xff;
			body[3] = (lt >> 16) & 0xff;
			body[4] = (lt >> 8) & 0xff;
			body[5] = lt & 0xff;
			memcpy(&body[6], &prefixes[i].prefix, pfx_bytes);

			off = append_opt(buf, cap, off,
					 24 /* Route Information */, len_units,
					 body, 2 + 4 + pfx_bytes);
			if (off < 0) return -1;
		}

		/* ── PIO for non-ML prefixes (RFC 4861 §4.6.2) ─────────
		 * Lets LAN hosts SLAAC a global addr in our OMR/on-mesh
		 * prefix.  Skipped for mesh-local since LAN hosts shouldn't
		 * pretend to be on the Thread mesh's L2.
		 *
		 * body: prefix_len(1) + flags(1) + valid_lifetime(4) +
		 *       preferred_lifetime(4) + reserved(4) + prefix(16).
		 * Total 30 bytes → option length = 4 (32 bytes incl 2B hdr). */
		if (!is_mesh_local) {
			uint8_t body[2 + 4 + 4 + 4 + 16];
			body[0] = plen;
			/* L=0 (NOT on-link), A=1 (autonomous SLAAC), R=0.
			 *
			 * On-link must be 0 because LAN hosts cannot reach
			 * Thread sensors via L2 ND on this link — they have
			 * to go through us (the BR) using the RIO route.
			 * Setting L=1 made Linux respond "Destination
			 * unreachable" after failed NS instead of routing
			 * via our RIO entry. */
			body[1] = 0x40;
			uint32_t valid = RA_RIO_LIFETIME_S;
			uint32_t pref  = RA_RIO_LIFETIME_S;
			body[2]  = (valid >> 24) & 0xff;
			body[3]  = (valid >> 16) & 0xff;
			body[4]  = (valid >>  8) & 0xff;
			body[5]  =  valid        & 0xff;
			body[6]  = (pref  >> 24) & 0xff;
			body[7]  = (pref  >> 16) & 0xff;
			body[8]  = (pref  >>  8) & 0xff;
			body[9]  =  pref         & 0xff;
			memset(&body[10], 0, 4);  /* reserved */
			memcpy(&body[14], &prefixes[i].prefix, 16);

			off = append_opt(buf, cap, off,
					 3 /* Prefix Information */, 4,
					 body, sizeof(body));
			if (off < 0) return -1;
		}

		prefix_count++;
	}

	*prefix_count_out = prefix_count;
	return off;
}

static void send_ra_now(void)
{
	struct net_if *wifi = get_wifi_iface();
	if (!wifi) {
		NN_LOG_DBG("send_ra: no WiFi iface");
		return;
	}
	if (!net_if_is_up(wifi)) {
		NN_LOG_DBG("send_ra: WiFi iface down");
		return;
	}

	/* Source must be the WiFi link-local; ND requires LL src for RAs. */
	struct net_in6_addr *src = net_if_ipv6_get_ll(wifi, NET_ADDR_PREFERRED);
	if (!src) {
		NN_LOG_DBG("send_ra: no LL src on WiFi");
		return;
	}

	uint8_t payload[256];
	int prefix_count = 0;
	int payload_len = build_ra_payload(wifi, payload, sizeof(payload),
					   &prefix_count);
	if (payload_len < 12) {
		NN_LOG_WRN("send_ra: build failed (%d)", payload_len);
		return;
	}
	if (prefix_count == 0) {
		NN_LOG_DBG("send_ra: no Thread prefixes yet — skip");
		return;
	}

	struct net_pkt *pkt = net_pkt_alloc_with_buffer(
		wifi, payload_len, NET_AF_INET6, NET_IPPROTO_ICMPV6,
		K_MSEC(200));
	if (!pkt) {
		NN_LOG_WRN("send_ra: pkt alloc failed");
		return;
	}
	net_pkt_set_ipv6_hop_limit(pkt, ND_HOP_LIMIT);

	if (net_ipv6_create(pkt, src, &ALL_NODES_MCAST) < 0 ||
	    net_icmpv6_create(pkt, 134 /* RA */, 0) < 0 ||
	    net_pkt_write(pkt, payload, payload_len) < 0) {
		NN_LOG_WRN("send_ra: header/payload write failed");
		net_pkt_unref(pkt);
		return;
	}

	net_pkt_cursor_init(pkt);
	if (net_ipv6_finalize(pkt, NET_IPPROTO_ICMPV6) < 0) {
		NN_LOG_WRN("send_ra: finalize failed");
		net_pkt_unref(pkt);
		return;
	}

	if (net_send_data(pkt) < 0) {
		NN_LOG_WRN("send_ra: net_send_data failed");
		net_pkt_unref(pkt);
		return;
	}

	/* Periodic log suppressed to NN_LOG_DBG to keep the shell responsive
	 * (every 30s × 4 lines fills the console queue).  Log the FIRST
	 * successful send at INFO so we can verify init worked. */
	static bool first_logged;
	if (!first_logged) {
		NN_LOG_INF("first RA sent: %d prefix(es), %d B payload",
			prefix_count, payload_len);
		first_logged = true;
	} else {
		NN_LOG_DBG("RA sent: %d prefix(es), %d B payload",
			prefix_count, payload_len);
	}
}

static void ra_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	send_ra_now();
	k_work_reschedule(&ra_work, K_SECONDS(RA_INTERVAL_S));
}

void ra_sender_start(void)
{
	if (s_started) {
		return;
	}
	k_work_init_delayable(&ra_work, ra_work_handler);
	s_started = true;
	/* First RA after a 5s delay so WiFi DAD + Thread sync_routes have
	 * time to settle. */
	k_work_reschedule(&ra_work, K_SECONDS(5));
	NN_LOG_INF("RA sender started — interval %ds, lifetime %ds",
		RA_INTERVAL_S, RA_RIO_LIFETIME_S);
}

void ra_sender_kick(void)
{
	if (!s_started) {
		/* Called before ra_sender_start() — common at boot when
		 * ncp_netif_sync_routes() runs before WiFi is up.  No-op:
		 * the periodic timer will pick up the new prefixes once
		 * ra_sender_start() finally fires. */
		return;
	}
	(void)k_work_cancel_delayable(&ra_work);
	k_work_reschedule(&ra_work, K_NO_WAIT);
}
