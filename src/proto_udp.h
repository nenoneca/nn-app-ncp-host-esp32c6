/* SPDX-License-Identifier: Apache-2.0 */
/*
 * proto_udp — gateway-side UDP transport on the Thread mesh.
 *
 *   - Listens on CONFIG_NN_PROTO_UDP_PORT for inbound nn_proto frames
 *     from devices (D2H pass-through, D2G commands).
 *   - Sends unicast to a device's mesh-local IPv6.
 *   - Sends Thread realm-local multicast (ff03::1) for G2D HELLO and
 *     hub-status announcements.
 *
 * Phase 2.D scope: socket plumbing + send/recv helpers.  Routing,
 * sig-verify, and gateway commands plug in on top.
 */

#ifndef PROTO_UDP_H_
#define PROTO_UDP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/net_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inbound frame handler.  buf/len are the entire UDP datagram (one
 * frame).  src is the sender's IPv6 address (so the routing layer can
 * cache device_id → IPv6).  port is the sender's source port. */
typedef void (*proto_udp_rx_fn)(const uint8_t *buf, size_t len,
				const struct in6_addr *src, uint16_t port,
				void *user);

struct proto_udp_config {
	uint16_t          port;
	proto_udp_rx_fn   on_rx;
	void             *on_rx_user;
};

int proto_udp_init(const struct proto_udp_config *cfg);

/* Send a frame to a unicast IPv6 destination on the configured port. */
int proto_udp_send_unicast(const struct in6_addr *dst, uint16_t dst_port,
			   const uint8_t *frame, size_t len);

/* Send a frame to Thread realm-local multicast (ff03::1) on the
 * configured port.  Used for HELLO + hub-status broadcast. */
int proto_udp_send_mcast(const uint8_t *frame, size_t len);

struct proto_udp_stats {
	uint32_t rx_frames;
	uint32_t rx_bytes;
	uint32_t rx_drops_oversize;
	uint32_t rx_drops_bad;
	uint32_t tx_unicast;
	uint32_t tx_mcast;
	uint32_t tx_failures;
};

void proto_udp_get_stats(struct proto_udp_stats *out);

#ifdef __cplusplus
}
#endif

#endif /* PROTO_UDP_H_ */
