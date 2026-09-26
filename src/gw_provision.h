/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
/*
 * gw_provision — moved to modules/libs/fw_common/include/fw_common/.
 * Shim kept so existing `#include "gw_provision.h"` callers in this app
 * (main.c, gw_ble_provision shim, …) compile unchanged.
 */
#include <fw_common/gw_provision.h>
