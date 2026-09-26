/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_commands — gateway-originated and gateway-terminated nn_proto
 * messages (D2G/G2D inner-cmd handlers).
 *
 *   - HELLO mcast emitter: every CONFIG_NN_PROTO_HELLO_INTERVAL_S
 *     seconds the gateway broadcasts GATEWAY_HELLO carrying its
 *     mesh-local IPv6 + advertise interval + current hub-online flag.
 *   - HUB_STATUS_ANNOUNCE on TCP up/down state changes.
 *   - HUB_STATUS_QUERY responder: D2G with cmd=0x0001 → unicast G2D
 *     reply to the requesting device with the current hub flag.
 */

#ifndef GW_COMMANDS_H_
#define GW_COMMANDS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/net_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the periodic HELLO timer + register the proto_tcp state
 * change hook.  Call once after gw_identity_init() and proto_udp_init(). */
int gw_commands_init(void);

/* Override / report the gateway's own mesh-local IPv6 (carried in HELLO).
 * Falls back to in6addr_any if never set. */
void gw_commands_set_mesh_local(const struct in6_addr *addr);

/* Driven by proto_tcp state changes (caller should invoke whenever the
 * TCP transport up/down state flips). */
void gw_commands_set_hub_online(bool online);

#ifdef __cplusplus
}
#endif

#endif /* GW_COMMANDS_H_ */
