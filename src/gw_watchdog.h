/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_watchdog — task watchdog wrapper.
 *
 * Registers a single task watchdog channel with a 60 s deadline, kicked
 * from a low-priority heartbeat thread.  Purpose: if the new image
 * deadlocks (e.g. a regression that wedges the proto_tcp worker, or a
 * panic-loop that doesn't naturally re-boot), the watchdog forces a
 * cold reset.  Combined with `gw_ota_init`'s deferred-confirm logic,
 * a wedged test-mode image gets reverted by MCUboot on the next boot.
 */

#ifndef GW_WATCHDOG_H_
#define GW_WATCHDOG_H_

#ifdef __cplusplus
extern "C" {
#endif

int gw_watchdog_init(void);

#ifdef __cplusplus
}
#endif

#endif /* GW_WATCHDOG_H_ */
