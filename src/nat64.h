/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Stateful NAT64 translator (RFC 6146 / RFC 6145).
 *
 * Direction: Thread IPv6 <-> WiFi IPv4.
 *
 * Outbound (Thread -> WiFi):
 *   ncp_netif_rx_stream_net() sees a packet with dst prefix 64:ff9b::/96
 *   and hands it to nat64_tx_v6().  We:
 *     1) derive the target IPv4 address from the last 32 bits
 *     2) find or allocate a session (keyed by v6_src + proto + port/id)
 *     3) rewrite headers into an IPv4 packet
 *     4) send via the WiFi iface (or log-and-drop if WiFi is down)
 *
 * Inbound (WiFi -> Thread):
 *   Future WiFi RX path calls nat64_rx_v4().  We look up the session
 *   by (v4_dst, proto, v4_dst_port / icmp_id), synthesize an IPv6
 *   packet with src 64:ff9b::<v4_src> and dst = original v6_src,
 *   then send via the Thread iface (STREAM_NET).
 *
 * Scope today: ICMPv6 Echo Request/Reply end-to-end; UDP + TCP are
 * stubbed.  ESP32-C6 Host with 32 sessions, ~2 min idle timeout.
 */

#ifndef NAT64_H_
#define NAT64_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define NAT64_MAX_SESSIONS 32

/* Return true iff the 128-bit `addr6` begins with 64:ff9b::/96 (16 bytes:
 * 00 64 ff 9b 00 00 00 00 00 00 00 00). */
bool nat64_is_wellknown(const uint8_t addr6[16]);

int nat64_init(void);

/* Handle an IPv6 packet with dst in 64:ff9b::/96.  Returns 0 on
 * success (packet translated and either TX'd or logged), negative on
 * error (caller can drop). */
int nat64_tx_v6(const uint8_t *ipv6_pkt, size_t pkt_len);

/* Called by wlan0 RX when an IPv4 packet arrives.  Returns 0 if the
 * packet was a NAT64 reply and was translated back to IPv6, or
 * -ENOENT if no session matches (caller should hand to Zephyr stack
 * normally). */
int nat64_rx_v4(const uint8_t *ipv4_pkt, size_t pkt_len);

struct nat64_stats {
	uint32_t tx_pkts;
	uint32_t rx_pkts;
	uint32_t rx_drops;        /* STREAM_NET forward to NCP failed */
	uint32_t tx_icmp6;
	uint32_t tx_udp;
	uint32_t tx_tcp;
	uint32_t tx_no_wifi;      /* translated but dropped (WiFi not up) */
	uint32_t tx_bad_packet;
	uint32_t sessions_active;
	uint32_t sessions_full;
};

void nat64_stats_get(struct nat64_stats *out);

#endif /* NAT64_H_ */
