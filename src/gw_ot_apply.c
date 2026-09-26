/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>

#include <nn_osal/osal.h>


#include "gw_ot_apply.h"
#include "ncp_link.h"
#include "spinel.h"

NN_OSAL_LOG_MODULE(gw_ot_apply);

#define SET_TIMEOUT  K_MSEC(2000)

/* OT operational dataset TLV types (Thread 1.x §8.10). */
#define TLV_CHANNEL          0
#define TLV_PANID            1
#define TLV_EXT_PANID        2
#define TLV_NETWORK_NAME     3
#define TLV_PSKC             4
#define TLV_NETWORK_KEY      5
#define TLV_MESH_LOCAL_PREFIX 7
#define TLV_SECURITY_POLICY  12
#define TLV_ACTIVE_TIMESTAMP 14
#define TLV_CHANNEL_MASK     53

static int set_raw(const char *label, uint32_t prop,
		   const uint8_t *v, size_t len)
{
	uint32_t ls = 0;
	int rv = ncp_link_set_raw(prop, v, len, &ls, SET_TIMEOUT);
	if (rv < 0) {
		NN_LOG_ERR("set %s (prop 0x%02x) failed: rv=%d ls=%u",
			label, prop, rv, ls);
		return rv;
	}
	NN_LOG_INF("set %s (prop 0x%02x, %zu B): ok", label, prop, len);
	return 0;
}

static int apply_channel(const uint8_t *v, uint8_t len)
{
	/* TLV body: [page (1)] [channel (2 BE)] = 3 bytes total. */
	if (len != 3) {
		NN_LOG_WRN("Channel TLV bad len %u (expected 3)", len);
		return -EINVAL;
	}
	uint16_t ch = ((uint16_t)v[1] << 8) | v[2];
	uint8_t  c  = (uint8_t)(ch & 0xff);
	return set_raw("PHY_CHAN", SPINEL_PROP_PHY_CHAN, &c, 1);
}

static int apply_panid(const uint8_t *v, uint8_t len)
{
	if (len != 2) {
		NN_LOG_WRN("PanID TLV bad len %u (expected 2)", len);
		return -EINVAL;
	}
	/* OT TLV is BE; Spinel u16 little-endian. */
	uint8_t le[2] = { v[1], v[0] };
	return set_raw("MAC_PANID", SPINEL_PROP_MAC_15_4_PANID, le, 2);
}

static int apply_xpanid(const uint8_t *v, uint8_t len)
{
	if (len != 8) {
		NN_LOG_WRN("ExtPanID TLV bad len %u", len);
		return -EINVAL;
	}
	return set_raw("NET_XPANID", SPINEL_PROP_NET_XPANID, v, 8);
}

static int apply_network_name(const uint8_t *v, uint8_t len)
{
	if (len == 0 || len > 16) {
		NN_LOG_WRN("NetworkName TLV bad len %u", len);
		return -EINVAL;
	}
	/* Spinel takes a NUL-terminated string. */
	uint8_t buf[17];
	memcpy(buf, v, len);
	buf[len] = '\0';
	return set_raw("NET_NETWORK_NAME", SPINEL_PROP_NET_NETWORK_NAME,
		       buf, (size_t)len + 1);
}

static int apply_network_key(const uint8_t *v, uint8_t len)
{
	if (len != 16) {
		NN_LOG_WRN("NetworkKey TLV bad len %u", len);
		return -EINVAL;
	}
	return set_raw("NET_NETWORK_KEY", SPINEL_PROP_NET_NETWORK_KEY, v, 16);
}

static int apply_mesh_local_prefix(const uint8_t *v, uint8_t len)
{
	/* OT TLV: 8 bytes (the /64 prefix).  Spinel IPV6_ML_PREFIX is
	 * 6C — a 16-byte IPv6 address followed by 1-byte prefix length.
	 * Pack the prefix into the high 8 bytes, zero the low 8, length=64. */
	if (len != 8) {
		NN_LOG_WRN("MeshLocalPrefix TLV bad len %u", len);
		return -EINVAL;
	}
	uint8_t buf[17] = { 0 };
	memcpy(buf, v, 8);
	buf[16] = 64;
	return set_raw("IPV6_ML_PREFIX", SPINEL_PROP_IPV6_ML_PREFIX, buf, 17);
}

int gw_ot_apply_dataset(const uint8_t *tlvs, size_t tlvs_len)
{
	if (!tlvs || tlvs_len == 0) {
		return -EINVAL;
	}

	/* NCP rejects PHY/MAC/NET property writes while Thread is up
	 * (last-status=4 invalid-state).  After a re-flash the NCP
	 * auto-restores its previous network from NVS during ncp_netif_init,
	 * so by the time we get here Thread is already alive — bring it
	 * back down so we can install the new dataset. */
	uint8_t down = 0;
	uint32_t ls = 0;
	(void)ncp_link_set_raw(SPINEL_PROP_NET_STACK_UP, &down, 1, &ls,
			       SET_TIMEOUT);
	(void)ncp_link_set_raw(SPINEL_PROP_NET_IF_UP, &down, 1, &ls,
			       SET_TIMEOUT);
	NN_LOG_INF("NCP brought down — applying new dataset");

	size_t i = 0;
	int rv;
	int applied = 0;

	while (i + 2 <= tlvs_len) {
		uint8_t t = tlvs[i];
		uint8_t l = tlvs[i + 1];
		if (i + 2 + l > tlvs_len) {
			NN_LOG_WRN("truncated TLV t=%u at offset %zu", t, i);
			return -EINVAL;
		}
		const uint8_t *v = &tlvs[i + 2];

		switch (t) {
		case TLV_CHANNEL:
			rv = apply_channel(v, l);
			if (rv) return rv;
			applied++;
			break;
		case TLV_PANID:
			rv = apply_panid(v, l);
			if (rv) return rv;
			applied++;
			break;
		case TLV_EXT_PANID:
			rv = apply_xpanid(v, l);
			if (rv) return rv;
			applied++;
			break;
		case TLV_NETWORK_NAME:
			rv = apply_network_name(v, l);
			if (rv) return rv;
			applied++;
			break;
		case TLV_NETWORK_KEY:
			rv = apply_network_key(v, l);
			if (rv) return rv;
			applied++;
			break;
		case TLV_MESH_LOCAL_PREFIX:
			rv = apply_mesh_local_prefix(v, l);
			if (rv) return rv;
			applied++;
			break;
		/* Skipped (NCP defaults are fine for first bring-up):
		 *   ActiveTimestamp, PSKc, SecurityPolicy, ChannelMask.
		 * Hub will push these later once we surface them in
		 * higher-level network management commands.
		 */
		case TLV_ACTIVE_TIMESTAMP:
		case TLV_PSKC:
		case TLV_SECURITY_POLICY:
		case TLV_CHANNEL_MASK:
			NN_LOG_DBG("skipping TLV t=%u (defaults)", t);
			break;
		default:
			NN_LOG_DBG("skipping unknown TLV t=%u len=%u", t, l);
			break;
		}
		i += 2 + l;
	}
	NN_LOG_INF("applied %d / %zu TLVs to NCP", applied, tlvs_len);
	return 0;
}
