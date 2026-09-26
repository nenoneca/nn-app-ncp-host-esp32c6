/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_ot_apply — push a hub-supplied OT operational dataset into the
 * paired NCP via Spinel.  The dataset is the canonical Thread TLV
 * blob (same format `ot dataset active -x` emits and Thread spec
 * §8.10 defines).  The TLV stream is decomposed into individual
 * Spinel SET ops (NET_NETWORK_KEY, NET_XPANID, MAC_15_4_PANID,
 * PHY_CHAN, etc.) so the NCP brings Thread up on the network the
 * hub asked for, rather than whatever it had baked-in or learned
 * from a previous run.
 *
 * Call AFTER ncp_link_init() and BEFORE flipping NET_IF_UP /
 * NET_STACK_UP — order matters.
 */

#ifndef GW_OT_APPLY_H_
#define GW_OT_APPLY_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decompose `tlvs` into Spinel SETs.  Returns 0 on success (every
 * recognised TLV applied without error) or a negative errno on the
 * first failure.  Unknown TLV types are silently skipped (forward
 * compatibility).
 */
int gw_ot_apply_dataset(const uint8_t *tlvs, size_t tlvs_len);

#ifdef __cplusplus
}
#endif

#endif /* GW_OT_APPLY_H_ */
