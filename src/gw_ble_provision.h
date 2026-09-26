/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
/*
 * gw_ble_provision — gateway BLE GATT provisioning service.  Body moved
 * to modules/libs/fw_common/ so it can be shared with the Linux gateway
 * daemon (host/gw_linux/).  This shim keeps the existing
 *   gw_ble_provision_start() / gw_ble_provision_stop()
 * API the app already calls.
 */

#include <fw_common/gw_ble_prov_zephyr.h>

#define gw_ble_provision_start  gw_ble_prov_zephyr_start
#define gw_ble_provision_stop   gw_ble_prov_zephyr_stop
