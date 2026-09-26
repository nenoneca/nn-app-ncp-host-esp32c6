/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>


#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>

#include "gw_commands.h"
#include "gw_identity.h"
#include "gw_thread_state.h"
#include "ncp_link.h"
#include "ncp_netif.h"
#include "proto_tcp.h"
#include "spinel.h"

#include <zephyr/net/net_ip.h>

NN_OSAL_LOG_MODULE(gw_thread_state);

/* Inner payload layout for GATEWAY_THREAD_STATE:
 *    1 B  Spinel net role (0=detached, 1=child, 2=router, 3=leader, 4=disabled)
 *    2 B  RLOC16 (little-endian)
 *   16 B  Mesh-local EID (full 128-bit IPv6 address)
 */
#define ARGS_LEN          (1 + 2 + 16)

#define GET_TIMEOUT       K_MSEC(500)
#ifndef CONFIG_NN_PROTO_THREAD_STATE_INTERVAL_S
#define CONFIG_NN_PROTO_THREAD_STATE_INTERVAL_S 30
#endif

static struct {
	struct k_work_delayable work;
	bool                    initialised;
	uint8_t                 last_role;
	uint16_t                last_rloc16;
	uint8_t                 last_mleid[16];   /* tracks change for ncp_netif resync */
} G;

static int read_state(uint8_t *role, uint16_t *rloc16, uint8_t mleid[16])
{
	uint8_t  buf[16];
	size_t   len;

	len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_NET_ROLE, buf, &len, GET_TIMEOUT);
	if (rv < 0 || len < 1) {
		NN_LOG_DBG("NET_ROLE rv=%d len=%zu", rv, len);
		return rv ? rv : -EIO;
	}
	*role = buf[0];

	len = sizeof(buf);
	rv = ncp_link_get(SPINEL_PROP_THREAD_RLOC16, buf, &len, GET_TIMEOUT);
	if (rv < 0 || len < 2) {
		NN_LOG_DBG("RLOC16 rv=%d len=%zu", rv, len);
		return rv ? rv : -EIO;
	}
	*rloc16 = nn_osal_get_le16(buf);

	len = 16;
	rv = ncp_link_get(SPINEL_PROP_IPV6_ML_ADDR, mleid, &len, K_MSEC(500));
	if (rv < 0 || len < 16) {
		NN_LOG_DBG("ML_ADDR rv=%d len=%zu", rv, len);
		return rv ? rv : -EIO;
	}
	return 0;
}

static void publish(void)
{
	if (proto_tcp_get_state() != PROTO_TCP_UP) {
		NN_LOG_DBG("skip publish — TCP not up");
		return;
	}
	const uint8_t *gw_id = gw_identity_get_id();
	if (!gw_id) {
		return;
	}

	uint8_t  role = 0;
	uint16_t rloc16 = 0;
	uint8_t  mleid[16] = { 0 };
	if (read_state(&role, &rloc16, mleid) < 0) {
		return;
	}

	uint8_t inner[2 + ARGS_LEN];
	nn_osal_put_le16(NN_PROTO_CMD_GATEWAY_THREAD_STATE, inner);
	inner[2] = role;
	nn_osal_put_le16(rloc16, inner + 3);
	memcpy(inner + 5, mleid, 16);

	uint8_t frame[NN_PROTO_OVERHEAD + GW_IDENTITY_ID_LEN + sizeof(inner)];
	int n = nn_proto_encode(NN_PROTO_TYPE_D2G,
				gw_id, GW_IDENTITY_ID_LEN,
				inner, sizeof(inner),
				gw_identity_sign, NULL,
				frame, sizeof(frame));
	if (n <= 0) {
		NN_LOG_WRN("encode rv=%d", n);
		return;
	}
	int rv = proto_tcp_enqueue(frame, (size_t)n);
	if (rv < 0) {
		NN_LOG_WRN("enqueue rv=%d", rv);
		return;
	}
	if (role != G.last_role || rloc16 != G.last_rloc16) {
		NN_LOG_INF("THREAD_STATE published: role=%u rloc16=0x%04x",
			role, rloc16);
		G.last_role = role;
		G.last_rloc16 = rloc16;
	} else {
		NN_LOG_DBG("THREAD_STATE published (steady): role=%u rloc16=0x%04x",
			role, rloc16);
	}
}

/* Keep the host-side dummy0 netif mirrored with NCP's current address
 * set, and tell gw_commands what mesh-local address to advertise in
 * GATEWAY_HELLO multicasts.  Without this:
 *   - dummy0's initial sync at boot can run before the NCP has its OMR
 *     address (NETDATA prefix may arrive later) → inbound D2H lands on
 *     an unbound dst and Zephyr drops it before reaching proto_udp.
 *   - gw_commands.G.mesh_local stays all-zero forever → HELLO args
 *     carry zeros and sensors fall back to the mcast source IP, which
 *     points at NCP-internal addresses we don't have bound on dummy0.
 * Re-running the mirror + setting the HELLO ML address every periodic
 * publish (~30 s) closes both gaps with one Spinel transaction. */
static void refresh_addr_mirror(const uint8_t mleid[16])
{
	if (memcmp(G.last_mleid, mleid, 16) != 0) {
		struct in6_addr addr;
		memcpy(&addr, mleid, 16);
		gw_commands_set_mesh_local(&addr);
		memcpy(G.last_mleid, mleid, 16);
	}
	int added = ncp_netif_sync_addresses();
	if (added > 0) {
		NN_LOG_INF("address mirror refreshed (+%d new)", added);
	}
}

static void worker(struct k_work *w)
{
	ARG_UNUSED(w);

	/* Read state first so we have a fresh ML-EID; reuse for mirror. */
	uint8_t  role = 0;
	uint16_t rloc16 = 0;
	uint8_t  mleid[16] = { 0 };
	if (read_state(&role, &rloc16, mleid) == 0) {
		refresh_addr_mirror(mleid);
	}

	publish();
	k_work_reschedule(&G.work,
			  K_SECONDS(CONFIG_NN_PROTO_THREAD_STATE_INTERVAL_S));
}

void gw_thread_state_init(void)
{
	if (G.initialised) {
		return;
	}
	memset(&G, 0, sizeof(G));
	G.initialised = true;
	k_work_init_delayable(&G.work, worker);
	k_work_reschedule(&G.work,
			  K_SECONDS(CONFIG_NN_PROTO_THREAD_STATE_INTERVAL_S));
	NN_LOG_INF("gw_thread_state ready (every %d s)",
		CONFIG_NN_PROTO_THREAD_STATE_INTERVAL_S);
}

void gw_thread_state_kick(void)
{
	if (!G.initialised) {
		return;
	}
	k_work_reschedule(&G.work, K_NO_WAIT);
}
