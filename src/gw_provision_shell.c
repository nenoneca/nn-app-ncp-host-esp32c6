/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Zephyr shell wrappers for the gateway provisioning store.  The core
 * now lives in modules/libs/fw_common/src/gw_provision.c (shared with
 * the Linux gateway daemon).  Only the developer-convenience shell
 * commands stay here — they touch zephyr/shell + sys_reboot which
 * have no Linux equivalent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* nn_osal_sys_reboot via nn_osal/system.h (included by osal.h) */

#include <nn_osal/osal.h>
#include <fw_common/gw_provision.h>

static int hex_decode(const char *hex, uint8_t *out, size_t want)
{
	size_t hex_len = strlen(hex);
	if (hex_len != want * 2) {
		return -EINVAL;
	}
	for (size_t i = 0; i < want; i++) {
		unsigned int byte;
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
			return -EINVAL;
		}
		out[i] = (uint8_t)byte;
	}
	return 0;
}

static int cmd_provision_set(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 7) {
		nn_osal_shell_print(sh,
			"usage: provision set <ssid> <psk> <hub_mdns> "
			"<hub_id_hex(16)> <hub_pubkey_hex(130)> "
			"<ot_dataset_hex>");
		return -EINVAL;
	}
	const char *ssid     = argv[1];
	const char *psk      = argv[2];
	const char *hub_mdns = argv[3];
	const char *hub_id_h  = argv[4];
	const char *hub_pub_h = argv[5];
	const char *ot_dataset_h = argv[6];

	uint8_t hub_id[GW_PROVISION_HUB_ID_LEN];
	uint8_t hub_pub[GW_PROVISION_HUB_PUB_LEN];
	uint8_t ot_dataset[GW_PROVISION_OT_DATASET_MAX];

	if (hex_decode(hub_id_h, hub_id, sizeof(hub_id)) < 0) {
		nn_osal_shell_error(sh, "hub_id must be %d-char hex",
			    GW_PROVISION_HUB_ID_LEN * 2);
		return -EINVAL;
	}
	if (hex_decode(hub_pub_h, hub_pub, sizeof(hub_pub)) < 0) {
		nn_osal_shell_error(sh, "hub_pubkey must be %d-char hex",
			    GW_PROVISION_HUB_PUB_LEN * 2);
		return -EINVAL;
	}
	if (hub_pub[0] != 0x04) {
		nn_osal_shell_error(sh, "hub_pubkey must start with 0x04 (uncompressed)");
		return -EINVAL;
	}
	size_t ot_hex_len = strlen(ot_dataset_h);
	if (ot_hex_len % 2 || ot_hex_len / 2 > GW_PROVISION_OT_DATASET_MAX) {
		nn_osal_shell_error(sh, "ot_dataset hex must be ≤%d chars",
			    GW_PROVISION_OT_DATASET_MAX * 2);
		return -EINVAL;
	}
	size_t ot_len = ot_hex_len / 2;
	if (hex_decode(ot_dataset_h, ot_dataset, ot_len) < 0) {
		nn_osal_shell_error(sh, "ot_dataset must be valid hex");
		return -EINVAL;
	}

	int rv = gw_provision_set(ssid, psk, hub_mdns, hub_id, hub_pub,
				  ot_dataset, ot_len);
	if (rv < 0) {
		nn_osal_shell_error(sh, "provision failed: %d", rv);
		return rv;
	}
	nn_osal_shell_print(sh, "provisioned — rebooting in 1 s...");
	nn_osal_sleep_ms(1000);
	nn_osal_sys_reboot(NN_OSAL_REBOOT_COLD);
	return 0;
}

static int cmd_provision_show(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	if (!gw_provision_is_complete()) {
		nn_osal_shell_print(sh, "not provisioned");
		return -ENODATA;
	}
	nn_osal_shell_print(sh, "ssid     : %s", gw_provision_get_ssid());
	nn_osal_shell_print(sh, "psk      : (%zu chars)", strlen(gw_provision_get_psk()));
	nn_osal_shell_print(sh, "hub_mdns : %s", gw_provision_get_hub_mdns());
	const uint8_t *id = gw_provision_get_hub_id();
	char id_hex[GW_PROVISION_HUB_ID_LEN * 2 + 1];
	for (int i = 0; i < GW_PROVISION_HUB_ID_LEN; i++) {
		snprintf(id_hex + i * 2, 3, "%02x", id[i]);
	}
	nn_osal_shell_print(sh, "hub_id   : %s", id_hex);

	const uint8_t *pub = gw_provision_get_hub_pubkey();
	char pub_hex[GW_PROVISION_HUB_PUB_LEN * 2 + 1];
	for (int i = 0; i < GW_PROVISION_HUB_PUB_LEN; i++) {
		snprintf(pub_hex + i * 2, 3, "%02x", pub[i]);
	}
	nn_osal_shell_print(sh, "hub_pub  : %s", pub_hex);
	return 0;
}

static int cmd_provision_clear(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	gw_provision_clear();
	nn_osal_shell_print(sh, "cleared — reboot to re-init");
	return 0;
}

static int cmd_provision_factory_reset(nn_osal_shell_ctx_t *sh,
				       size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	nn_osal_shell_print(sh, "wiping provisioning + rebooting in 1 s...");
	gw_provision_clear();
	nn_osal_sleep_ms(1000);
	nn_osal_sys_reboot(NN_OSAL_REBOOT_COLD);
	return 0;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(prov_subs,
	NN_OSAL_SHELL_CMD(set, cmd_provision_set,
		  "set <ssid> <psk> <hub_mdns> <hub_id_hex(16)> "
		  "<hub_pub_hex(130)> <ot_dataset_hex>"),
	NN_OSAL_SHELL_CMD(show, cmd_provision_show, "Show current provisioning"),
	NN_OSAL_SHELL_CMD(clear, cmd_provision_clear, "Wipe provisioning NVS"),
	NN_OSAL_SHELL_CMD(factory_reset, cmd_provision_factory_reset, "Wipe provisioning NVS + reboot"),
	NN_OSAL_SHELL_SUBCMD_SET_END
);
NN_OSAL_SHELL_CMD_REGISTER_SET(provision, &prov_subs, NULL, "Gateway provisioning (WiFi creds + hub identity)");
