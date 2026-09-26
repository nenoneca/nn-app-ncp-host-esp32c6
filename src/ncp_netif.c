/* SPDX-License-Identifier: Apache-2.0 */

#include "ncp_netif.h"
#include "ncp_link.h"
#include "spinel.h"
#include "border_agent.h"

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>

#include <nn_osal/osal.h>

NN_OSAL_LOG_MODULE(ncp_netif);

#define NCP_MTU 1280  /* Thread = IPv6 base MTU */

static struct net_if       *g_iface;
static uint8_t              g_eui64[8];
static bool                 g_eui64_valid;
static struct k_mutex       stats_lock;
static struct ncp_netif_stats stats;

/* ---------- L2 send: wrap IPv6 packet in STREAM_NET SET and push ---------- */

static int ncp_dummy_send(const struct device *dev, struct net_pkt *pkt)
{
	ARG_UNUSED(dev);

	/* OTA quiet mode: NCP is in MCUboot doing a swap and isn't running
	 * its Spinel decoder.  If we keep pushing STREAM_NET frames they
	 * accumulate as garbage in NCP's UART1 RX FIFO and the new image's
	 * HDLC framer can't resync.  Drop quietly — Thread will retransmit
	 * lost frames after the link recovers. */
	if (ncp_link_is_quiet_for_ota()) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_drops++;
		k_mutex_unlock(&stats_lock);
		return 0;  /* return 0 so net stack doesn't retry immediately */
	}

	size_t total = net_pkt_get_len(pkt);
	if (total == 0 || total > NCP_MTU) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("tx drop: bad len %zu", total);
		return -EINVAL;
	}

	/* STREAM_NET payload: uint16 LE length + packet bytes.  Metadata empty. */
	uint8_t payload[2 + NCP_MTU];
	payload[0] = (uint8_t)(total & 0xff);
	payload[1] = (uint8_t)(total >> 8);

	if (net_pkt_read(pkt, payload + 2, total) < 0) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("tx drop: net_pkt_read failed");
		return -EIO;
	}

	uint32_t last_status = 0;
	int rv = ncp_link_set_raw(SPINEL_PROP_STREAM_NET,
				  payload, 2 + total,
				  &last_status, K_MSEC(500));
	if (rv < 0) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.tx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("tx drop: STREAM_NET rv=%d last-status=%u",
			rv, last_status);
		return rv;
	}

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_packets++;
	stats.tx_bytes += (uint32_t)total;
	k_mutex_unlock(&stats_lock);
	return 0;
}

/* ---------- L2 init: set link address ---------- */

static void ncp_iface_init(struct net_if *iface)
{
	g_iface = iface;

	if (g_eui64_valid) {
		net_if_set_link_addr(iface, g_eui64, sizeof(g_eui64),
				     NET_LINK_IEEE802154);
	}
	/*
	 * Thread is an IPv6-only link; the NCP does its own ND/MLD over
	 * 802.15.4, and any addresses we mirror onto this iface are
	 * already "owned" by the NCP — so DAD from us would see the NCP
	 * answer and treat our mirror as a duplicate.  Disable ND+MLD.
	 */
	net_if_flag_set(iface, NET_IF_IPV6);
	net_if_flag_set(iface, NET_IF_IPV6_NO_ND);
	net_if_flag_set(iface, NET_IF_IPV6_NO_MLD);
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
}

static struct dummy_api ncp_netif_api = {
	.iface_api.init = ncp_iface_init,
	.send = ncp_dummy_send,
};

/* No underlying device; L2 callbacks carry everything.  init_fn NULL. */
NET_DEVICE_INIT(ncp_thread_netif, "ncp_thread",
		NULL, NULL, NULL, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&ncp_netif_api,
		DUMMY_L2, NET_L2_GET_CTX_TYPE(DUMMY_L2), NCP_MTU);

/* ---------- Public API ---------- */

struct net_if *ncp_netif_get(void)
{
	return g_iface;
}

int ncp_netif_init(void)
{
	k_mutex_init(&stats_lock);

	uint8_t hw[8];
	size_t  hwlen = sizeof(hw);
	int rv = ncp_link_get(SPINEL_PROP_HWADDR, hw, &hwlen, K_MSEC(500));
	if (rv == 0 && hwlen == 8) {
		memcpy(g_eui64, hw, 8);
		g_eui64_valid = true;
		NN_LOG_INF("thread-over-spinel EUI-64: "
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			hw[0], hw[1], hw[2], hw[3],
			hw[4], hw[5], hw[6], hw[7]);
		/* If the iface was inited before we had HWADDR, set it now. */
		if (g_iface) {
			net_if_set_link_addr(g_iface, g_eui64,
					     sizeof(g_eui64),
					     NET_LINK_IEEE802154);
		}
	} else {
		NN_LOG_WRN("HWADDR get failed rv=%d len=%zu; link addr deferred",
			rv, hwlen);
	}

	if (g_iface) {
		net_if_up(g_iface);
		NN_LOG_INF("thread-over-spinel iface up (ifidx=%d)",
			net_if_get_by_iface(g_iface));
	}
	return 0;
}

/* ---------- Inbound from ncp_link ---------- */

void ncp_netif_rx_stream_net(const uint8_t *value, size_t value_len)
{
	if (!g_iface) {
		NN_LOG_WRN("rx drop: iface not up");
		return;
	}
	if (value_len < 2) {
		NN_LOG_WRN("rx drop: short STREAM_NET (%zu)", value_len);
		return;
	}
	uint16_t pkt_len = (uint16_t)value[0] | ((uint16_t)value[1] << 8);
	if (pkt_len == 0 || (size_t)pkt_len > value_len - 2 || pkt_len > NCP_MTU) {
		NN_LOG_WRN("rx drop: bad pkt_len=%u value_len=%zu", pkt_len, value_len);
		return;
	}
	const uint8_t *ipbuf = value + 2;

	/* [diag] Off-mesh STREAM_NET packets (NAT64 candidates).  Skip the
	 * intra-mesh MLE/anycast traffic that dominates the volume. */
	if (IS_ENABLED(CONFIG_NCP_NETIF_LOG_RX_OFFMESH) &&
	    pkt_len >= 40 && (ipbuf[0] >> 4) == 6) {
		uint8_t nh = ipbuf[6];
		const uint8_t *src = ipbuf + 8;
		const uint8_t *dst = ipbuf + 24;
		uint16_t sp = 0, dp = 0;
		if (pkt_len >= 48 && nh == 17) {
			sp = ((uint16_t)ipbuf[40] << 8) | ipbuf[41];
			dp = ((uint16_t)ipbuf[42] << 8) | ipbuf[43];
		}
		/* Skip MLE (port 19788) and anycast (port 61631) chatter. */
		if (sp != 19788 && dp != 19788 && sp != 61631 && dp != 61631) {
			printk("nrx: nh=%u len=%u "
			       "src=...:%02x%02x:%02x%02x:%02x%02x:%02x%02x "
			       "dst=...:%02x%02x:%02x%02x:%02x%02x:%02x%02x "
			       "sp=%u dp=%u\n",
			       nh, pkt_len,
			       src[8], src[9], src[10], src[11],
			       src[12], src[13], src[14], src[15],
			       dst[8], dst[9], dst[10], dst[11],
			       dst[12], dst[13], dst[14], dst[15],
			       sp, dp);
		}
	}

	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(
		g_iface, pkt_len, NET_AF_UNSPEC, 0, K_NO_WAIT);
	if (!pkt) {
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.rx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("rx drop: pkt alloc failed (%u)", pkt_len);
		return;
	}
	if (net_pkt_write(pkt, ipbuf, pkt_len) < 0) {
		net_pkt_unref(pkt);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.rx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("rx drop: net_pkt_write failed");
		return;
	}
	net_pkt_set_iface(pkt, g_iface);
	/* Treat as received IPv6: AF is set from version nibble by net_ipv6_input. */
	net_pkt_cursor_init(pkt);

	if (net_recv_data(g_iface, pkt) < 0) {
		net_pkt_unref(pkt);
		k_mutex_lock(&stats_lock, K_FOREVER);
		stats.rx_drops++;
		k_mutex_unlock(&stats_lock);
		NN_LOG_WRN("rx drop: net_recv_data failed");
		return;
	}

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.rx_packets++;
	stats.rx_bytes += pkt_len;
	k_mutex_unlock(&stats_lock);
}

void ncp_netif_stats_get(struct ncp_netif_stats *out)
{
	k_mutex_lock(&stats_lock, K_FOREVER);
	*out = stats;
	k_mutex_unlock(&stats_lock);
}

/* ---------- Address & route mirroring ---------- */

/*
 * Parse IPV6_ADDRESS_TABLE format: A(t(6CLL)).  Each t() is preceded by
 * a uint16 LE length.  Fields: 16-byte IPv6 addr, 1-byte prefix_len,
 * 4-byte preferred, 4-byte valid lifetime.
 */
int ncp_netif_sync_addresses(void)
{
	if (!g_iface) {
		return -ENODEV;
	}
	uint8_t buf[512];
	size_t  len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_IPV6_ADDRESS_TABLE,
			      buf, &len, K_MSEC(500));
	if (rv < 0) {
		NN_LOG_WRN("sync-addrs: GET ADDRESS_TABLE rv=%d", rv);
		return rv;
	}

	int added = 0;
	size_t off = 0;
	while (off + 2 <= len) {
		uint16_t slen = (uint16_t)buf[off] | ((uint16_t)buf[off + 1] << 8);
		off += 2;
		if (off + slen > len || slen < 16 + 1 + 4 + 4) {
			break;
		}
		const uint8_t *e = buf + off;
		struct net_in6_addr a6;
		memcpy(&a6, e, 16);

		if (!net_if_ipv6_addr_lookup_by_iface(g_iface, &a6)) {
			uint32_t valid = (uint32_t)e[21] | ((uint32_t)e[22] << 8) |
					 ((uint32_t)e[23] << 16) | ((uint32_t)e[24] << 24);
			uint32_t lifetime = (valid == 0xFFFFFFFFu) ? 0 : valid;
			struct net_if_addr *ifa = net_if_ipv6_addr_add(
				g_iface, &a6, NET_ADDR_MANUAL, lifetime);
			if (ifa) {
				added++;
				char str[NET_IPV6_ADDR_LEN];
				net_addr_ntop(NET_AF_INET6, &a6, str, sizeof(str));
				NN_LOG_INF("addr add: %s", str);
			} else {
				NN_LOG_WRN("addr add failed");
			}
		}
		off += slen;
	}
	return added;
}

static int add_prefix(struct net_in6_addr *prefix6, uint8_t plen)
{
	struct net_if_ipv6_prefix *p = net_if_ipv6_prefix_add(
		g_iface, prefix6, plen, 0xffffffff);
	if (!p) {
		return 0;
	}
	char str[NET_IPV6_ADDR_LEN];
	net_addr_ntop(NET_AF_INET6, prefix6, str, sizeof(str));
	NN_LOG_INF("prefix add: %s/%u", str, plen);
	return 1;
}

/* Forward declaration so we don't need to pull ra_sender.h into headers
 * that other files include — kick is a fire-and-forget. */
extern void ra_sender_kick(void);

int ncp_netif_sync_routes(void)
{
	if (!g_iface) {
		return -ENODEV;
	}

	int added = 0;

	/* Mesh-local prefix is implicit; not in ON_MESH_NETS.  Grab it
	 * explicitly so ML addresses on the iface are recognised as
	 * on-link. */
	uint8_t ml[20]; size_t mllen = sizeof(ml);
	if (ncp_link_get(SPINEL_PROP_IPV6_ML_PREFIX, ml, &mllen, K_MSEC(500)) == 0
	    && mllen >= 17) {
		struct net_in6_addr prefix6;
		memcpy(&prefix6, ml, 16);
		added += add_prefix(&prefix6, ml[16]);
	}

	uint8_t buf[512];
	size_t  len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_THREAD_ON_MESH_NETS,
			      buf, &len, K_MSEC(500));
	if (rv < 0) {
		NN_LOG_WRN("sync-routes: GET ON_MESH_NETS rv=%d", rv);
		return added > 0 ? added : rv;
	}
	size_t off = 0;
	while (off + 2 <= len) {
		uint16_t slen = (uint16_t)buf[off] | ((uint16_t)buf[off + 1] << 8);
		off += 2;
		if (off + slen > len || slen < 16 + 1) {
			break;
		}
		const uint8_t *e = buf + off;
		struct net_in6_addr prefix6;
		memcpy(&prefix6, e, 16);
		added += add_prefix(&prefix6, e[16]);
		off += slen;
	}
	if (added > 0) {
		/* Tell the RA sender to push out a fresh advertisement so
		 * LAN-side hosts learn the new route promptly instead of
		 * waiting up to RA_INTERVAL_S for the next periodic. */
		ra_sender_kick();
	}
	return added;
}
