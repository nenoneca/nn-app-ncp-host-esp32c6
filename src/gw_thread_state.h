/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Periodic D2G GATEWAY_THREAD_STATE reporter.
 *
 * Reads NET_ROLE, THREAD_RLOC16, IPV6_ML_ADDR from the NCP via Spinel
 * and sends them to the hub as a signed D2G frame.  Lets the hub
 * surface per-gateway Thread role/rloc16/mleid in `nn-hub network
 * show` and `nn-hub gateway info`.
 */

#ifndef GW_THREAD_STATE_H_
#define GW_THREAD_STATE_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Schedule the periodic reporter.  Idempotent. */
void gw_thread_state_init(void);

/* Force an immediate publish (e.g. on TCP up).  No-op if not initialised. */
void gw_thread_state_kick(void);

#ifdef __cplusplus
}
#endif

#endif /* GW_THREAD_STATE_H_ */
