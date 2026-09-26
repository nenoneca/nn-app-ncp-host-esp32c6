/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Virtual "Thread-over-Spinel" net_if.
 *
 * Outbound: Zephyr's networking stack hands IPv6 packets to this iface
 * when their destination matches a route on it; the dummy L2 `send`
 * callback wraps the packet in a Spinel SET(STREAM_NET) frame and
 * transmits it on the UART1 Spinel link to the NCP.
 *
 * Inbound: unsolicited PROP_VALUE_IS(STREAM_NET) frames coming from the
 * NCP are delivered here by ncp_link.c and turned into Zephyr net_pkt
 * instances, then fed to net_recv_data() on this iface.
 */

#ifndef NCP_NETIF_H_
#define NCP_NETIF_H_

#include <stddef.h>
#include <stdint.h>

struct net_if;

/* Bring up the net_if; must be called after ncp_link_init().  Fetches
 * HWADDR from the NCP and uses it as the link-layer address. */
int ncp_netif_init(void);

/*
 * One-shot sync: fetch the NCP's IPV6_ADDRESS_TABLE and mirror all
 * entries onto the Thread-over-Spinel iface.  Removes any previously
 * mirrored addresses not in the current table.  Returns number of
 * addresses registered, or negative on error.
 */
int ncp_netif_sync_addresses(void);

/*
 * One-shot sync: fetch THREAD_ON_MESH_NETS prefixes and install a route
 * for each (destination via the Thread-over-Spinel iface).  Returns
 * number of routes installed, or negative.
 */
int ncp_netif_sync_routes(void);

/* Return the Thread-over-Spinel net_if, or NULL if not up. */
struct net_if *ncp_netif_get(void);

/*
 * Handle an inbound STREAM_NET frame payload — i.e. the `value` bytes
 * of PROP_VALUE_IS(STREAM_NET, ...).  Called from ncp_link.c on the RX
 * thread.  Layout: <uint16 LE packet length><packet bytes><metadata?>.
 */
void ncp_netif_rx_stream_net(const uint8_t *value, size_t value_len);

struct ncp_netif_stats {
	uint32_t tx_packets;
	uint32_t tx_bytes;
	uint32_t tx_drops;
	uint32_t rx_packets;
	uint32_t rx_bytes;
	uint32_t rx_drops;
};

void ncp_netif_stats_get(struct ncp_netif_stats *out);

#endif /* NCP_NETIF_H_ */
