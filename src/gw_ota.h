/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_ota — gateway-side OTA over HTTP.
 *
 * Pulls a firmware image from
 *
 *     http://<hub_mdns>:CONFIG_NN_PROTO_HUB_FW_PORT/gw_firmware/<type>/<version>
 *
 * into the secondary MCUboot slot via Zephyr's flash_img APIs, then
 * `boot_request_upgrade(BOOT_UPGRADE_TEST)` and `sys_reboot()`.
 *
 * v1: explicit shell-triggered (`gw ota check|download <type> <ver>|apply`).
 * G2H/H2G command path lands when proto_router gets a generic command
 * dispatcher.
 */

#ifndef GW_OTA_H_
#define GW_OTA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int gw_ota_init(void);

/* Download <device_type>/<version> from the provisioned hub into slot1
 * and (optionally) request the test upgrade.  Returns the number of
 * bytes written on success, negative errno on failure. */
int gw_ota_download(const char *device_type, const char *version,
		    bool request_upgrade_after);

/* Mark the running image as confirmed (permanent).  Idempotent. */
int gw_ota_confirm(void);

#ifdef __cplusplus
}
#endif

#endif /* GW_OTA_H_ */
