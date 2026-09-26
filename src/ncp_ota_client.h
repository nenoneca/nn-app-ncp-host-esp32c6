/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ncp_ota_client — host side of the NCP OTA relay.
 *
 *   1. Pull NCP firmware bytes from the hub over HTTP (same path the
 *      ncp_host uses for its own image).
 *   2. Stream them over the existing Spinel UART1 link to the NCP using
 *      a custom vendor property.
 *   3. Issue the NCP-side finalise command, then reset.
 *
 * v1 status: API exposed, HTTP fetch wired, but the **Spinel vendor
 * property write path is a stub** — adding it requires extending the
 * Zephyr OT NCP module (subclass `Ncp::NcpBase` and register a vendor
 * property handler).  See feedback_ncp_ota_spinel_relay.md.
 *
 * Until that work lands, NCP firmware updates require physical esptool
 * flash on the NCP chip's USB-Serial-JTAG endpoint.
 */

#ifndef NCP_OTA_CLIENT_H_
#define NCP_OTA_CLIENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Spinel vendor property IDs.  OT reserves 0x3C00–0x3FFF for vendors
 * (SPINEL_PROP_VENDOR__BEGIN, see spinel.h:5097); ESP's sub-range is
 * 0x3C00–0x3C7F.  Vendor handlers in NcpBase only fire for keys in
 * that range — earlier 0x3500/0x3501 picks were outside it.
 * The NCP firmware registers these via OPENTHREAD_ENABLE_NCP_VENDOR_HOOK
 * + VendorSetPropertyHandler (no NcpBase subclass needed). */
#define NN_SPINEL_PROP_NCP_OTA_BLOCK         0x3C00u
#define NN_SPINEL_PROP_NCP_OTA_FINALIZE      0x3C01u
#define NN_SPINEL_PROP_NCP_OTA_CONFIRM       0x3C02u
#define NN_SPINEL_PROP_NCP_OTA_APP_VERSION   0x3C03u  /* GET: utf8 version */

/* Block size we'll write to slot1 per Spinel write.  Sized to fit in
 * one HDLC frame after Spinel header overhead and worst-case escape:
 * 256B is the conservative bring-up value; bump to 1024 once stable. */
#define NN_NCP_OTA_BLOCK_SIZE 256

/* Download <device_type>/<version> from the hub and stream it to the
 * paired NCP via vendor BLOCK/FINALIZE properties, then poll NCP_VERSION
 * until the new image boots and CONFIRM the swap.  Returns the number
 * of bytes streamed on success, or a negative errno on failure
 * (-EBUSY if another OTA is in progress, -EAGAIN if not provisioned,
 * -EBADMSG on sha256 mismatch, -ETIMEDOUT if NCP doesn't come back). */
int ncp_ota_relay(const char *device_type, const char *version);

/* Send CONFIRM to the NCP independently of a relay (e.g. after manually
 * flashing the NCP with esptool).  make_permanent=true makes the
 * running NCP image stay across reboots; false leaves the test bit set
 * so the next reboot reverts to slot0. */
int ncp_ota_confirm(bool make_permanent);

/* Query the NCP's app version (Spinel vendor GET 0x3C03).  On success
 * returns 0 and writes a NUL-terminated UTF8 string into out (truncated
 * to cap-1).  Returns -ETIMEDOUT if the Spinel link is down,
 * -ENOTSUP if the NCP firmware lacks the vendor hook (PROP_NOT_FOUND). */
int ncp_ota_get_app_version(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NCP_OTA_CLIENT_H_ */
