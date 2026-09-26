/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Border Agent UDP forwarder.
 *
 * Listens on UDP :49191 over the WiFi iface and tunnels commissioner
 * traffic to the NCP's OpenThread Border Agent via Spinel
 * UDP_FORWARD_STREAM.  Replies from the NCP come back via the same
 * Spinel property and are sent to the original commissioner peer.
 */

#ifndef BORDER_AGENT_H_
#define BORDER_AGENT_H_

#include <stddef.h>
#include <stdint.h>

#define BORDER_AGENT_PORT 49191

int border_agent_init(void);

/* Diagnostic: wrap the commissioner UDP payload as an IPv6 packet and
 * send it via STREAM_NET (alternate to UDP_FORWARD).  Used to test the
 * theory that OT's BA silently drops UDP_FORWARD-routed ClientHellos. */
int border_agent_try_stream_net_tx(const uint8_t *payload, size_t payload_len,
				   uint16_t commissioner_port,
				   const uint8_t commissioner_v4[4]);

#include <stdbool.h>

/* Inbound STREAM_NET demux for BA replies.  Called from
 * ncp_netif_rx_stream_net before the regular nat64.c path, so a
 * NCP→host reply destined for an active commissioner session goes
 * directly to the BA UDP listener instead of being dropped by
 * nat64.c's session matcher (which has no entry for externally-
 * originated commissioner traffic).  Returns true iff the packet
 * matched a session and was forwarded; caller should suppress further
 * nat64 processing in that case. */
bool border_agent_demux_inbound(const uint8_t v4_dst[4],
				uint16_t udp_dst_port,
				const uint8_t *udp_payload,
				size_t udp_payload_len);

struct border_agent_stats {
	uint32_t rx_from_commissioner;   /* UDP pkts we received on :49191 */
	uint32_t tx_to_ncp;              /* forwarded to NCP via Spinel */
	uint32_t rx_from_ncp;            /* NCP -> us (replies) */
	uint32_t tx_to_commissioner;     /* sent back out via UDP */
	uint32_t drops;
};

void border_agent_stats_get(struct border_agent_stats *out);

#endif /* BORDER_AGENT_H_ */
