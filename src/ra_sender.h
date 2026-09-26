/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ra_sender.h — periodic IPv6 Router Advertisement emitter on the WiFi netif.
 *
 * Advertises the Thread mesh-local + on-mesh prefixes as RFC 4191 Route
 * Information Options, so any IPv6 host on the same WiFi/LAN broadcast
 * domain auto-installs a route towards this NCP-host (acting as TBR).
 *
 * One-time Linux config to accept /64 RIOs:
 *   sudo sysctl -w net.ipv6.conf.<iface>.accept_ra_rt_info_max_plen=64
 */

#ifndef NCP_HOST_RA_SENDER_H_
#define NCP_HOST_RA_SENDER_H_

/* Start the periodic RA emitter.  Idempotent. */
void ra_sender_start(void);

/* Trigger one immediate RA emission (e.g. after sync_routes finds new
 * Thread prefixes).  Safe to call from any context — schedules work on
 * the system workqueue. */
void ra_sender_kick(void);

#endif /* NCP_HOST_RA_SENDER_H_ */
