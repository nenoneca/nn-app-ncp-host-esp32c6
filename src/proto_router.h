/* SPDX-License-Identifier: Apache-2.0 */
/*
 * proto_router — gateway-side broker glue.
 *
 * Plumbs:
 *   UDP (Thread side) RX → routing decision → TCP (hub side) TX
 *   TCP (hub side)    RX → routing decision → UDP (Thread side) TX
 *
 * For D2H/H2D the gateway forwards opaquely (no inner inspection,
 * no re-signing).  For D2G/G2D the gateway terminates / originates.
 *
 * Maintains a small device_id → mesh-local IPv6 routing table,
 * populated from incoming D2H/D2G source addresses.  Phase 2.E ships
 * a fixed-size LRU.  Per-device queueing is deferred to a follow-up.
 */

#ifndef PROTO_ROUTER_H_
#define PROTO_ROUTER_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/net_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <nn_osal/shell.h>

#define PROTO_ROUTER_DEVICE_ID_MAX  16   /* on-the-wire still 65535-cap */
#define PROTO_ROUTER_TABLE_SIZE     CONFIG_NN_PROTO_ROUTER_TABLE_SIZE

int  proto_router_init(void);

/* Inbound from device side.  Frame pointer + length are the bytes the
 * proto_udp callback received.  src is the IPv6 the frame came from
 * (used to update routing).
 *
 * Returns 0 on success (frame routed/handled), negative on drop. */
int  proto_router_on_udp_rx(const uint8_t *frame, size_t len,
			    const struct in6_addr *src);

/* Inbound from hub side.  Frame is one nn_proto frame fully buffered.
 * Returns 0 on success, negative on drop. */
int  proto_router_on_tcp_rx(const uint8_t *frame, size_t len);

/* Manual routing-table operations (used by the gateway-commands layer
 * for HELLO learning + by the shell for diagnostics). */
int  proto_router_remember(const uint8_t *device_id, uint16_t did_size,
			   const struct in6_addr *addr);
int  proto_router_lookup(const uint8_t *device_id, uint16_t did_size,
			 struct in6_addr *out_addr);

struct proto_router_stats {
	uint32_t in_d2h;
	uint32_t in_h2d;
	uint32_t in_d2g;
	uint32_t in_g2d;
	uint32_t fwd_d2h_to_tcp;
	uint32_t fwd_h2d_to_udp;
	uint32_t drops_unknown_did;
	uint32_t drops_tcp_enqueue;
	uint32_t drops_udp_send;
	uint32_t drops_bad_type;
	uint32_t table_inserts;
	uint32_t table_evictions;
};

void proto_router_get_stats(struct proto_router_stats *out);
void proto_router_dump_table(nn_osal_shell_ctx_t *sh);

#ifdef __cplusplus
}
#endif

#endif /* PROTO_ROUTER_H_ */
