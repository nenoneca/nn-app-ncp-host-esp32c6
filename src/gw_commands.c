/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>


#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>

#include "gw_identity.h"
#include "gw_commands.h"
#include "gw_provision.h"
#include "gw_thread_state.h"
#include "proto_tcp.h"
#include "proto_udp.h"
#include "proto_router.h"

NN_OSAL_LOG_MODULE(gw_commands);

#define UDP_PORT          CONFIG_NN_PROTO_UDP_PORT
#define HELLO_INTERVAL_S  CONFIG_NN_PROTO_HELLO_INTERVAL_S

/* HELLO args layout (matches docs/protocol/nn_proto.md):
 *   16 B  gateway mesh-local IPv6
 *    2 B  advertise interval (seconds, LE)
 *    1 B  hub-online flag (0 = down, 1 = up)
 */
#define HELLO_ARGS_LEN    (16 + 2 + 1)

/* HUB_STATUS_ANNOUNCE args: 1 B online flag. */
#define HUBSTAT_ARGS_LEN  1

static struct {
	struct k_work_delayable hello_work;
	struct in6_addr         mesh_local;
	bool                    hub_online;
} G;

/* ── frame helpers ─────────────────────────────────────────────────────── */

/* Build (sign + return frame size in *out_len) a G2D frame.
 * device_id may be NULL for multicast. */
static int build_g2d(uint16_t cmd, const uint8_t *args, size_t args_len,
		     const uint8_t *device_id, uint16_t did_size,
		     uint8_t *out_buf, size_t out_buf_size,
		     size_t *out_len)
{
	uint8_t inner[2 + HELLO_ARGS_LEN];
	if (2 + args_len > sizeof(inner)) {
		return -EINVAL;
	}
	nn_osal_put_le16(cmd, inner);
	if (args_len) {
		memcpy(inner + 2, args, args_len);
	}
	int n = nn_proto_encode(NN_PROTO_TYPE_G2D,
				device_id, did_size,
				inner, 2 + args_len,
				gw_identity_sign, NULL,
				out_buf, out_buf_size);
	if (n <= 0) {
		return n;
	}
	*out_len = (size_t)n;
	return 0;
}

/* ── HELLO (multicast) ─────────────────────────────────────────────────── */

static void send_hello(void)
{
	uint8_t args[HELLO_ARGS_LEN];
	memcpy(args, &G.mesh_local, 16);
	nn_osal_put_le16((uint16_t)HELLO_INTERVAL_S, args + 16);
	args[18] = G.hub_online ? 1 : 0;

	uint8_t  frame[NN_PROTO_OVERHEAD + HELLO_ARGS_LEN + 2];
	size_t   flen = 0;
	int rv = build_g2d(NN_PROTO_CMD_GATEWAY_HELLO, args, sizeof(args),
			   NULL, 0,
			   frame, sizeof(frame), &flen);
	if (rv < 0) {
		NN_LOG_WRN("HELLO build rv=%d", rv);
		return;
	}
	rv = proto_udp_send_mcast(frame, flen);
	if (rv < 0) {
		NN_LOG_WRN("HELLO send rv=%d", rv);
	} else {
		NN_LOG_DBG("HELLO mcast sent (online=%d, %zu B)",
			G.hub_online, flen);
	}
}

static void hello_timer(struct k_work *w)
{
	ARG_UNUSED(w);
	send_hello();
	k_work_reschedule(&G.hello_work, K_SECONDS(HELLO_INTERVAL_S));
}

/* ── HUB_STATUS_ANNOUNCE (mcast on flip) ──────────────────────────────── */

static void send_hub_status_announce(void)
{
	uint8_t  args[HUBSTAT_ARGS_LEN] = { G.hub_online ? 1 : 0 };
	uint8_t  frame[NN_PROTO_OVERHEAD + HUBSTAT_ARGS_LEN + 2];
	size_t   flen = 0;
	int rv = build_g2d(NN_PROTO_CMD_HUB_STATUS_ANNOUNCE,
			   args, sizeof(args),
			   NULL, 0,
			   frame, sizeof(frame), &flen);
	if (rv < 0) {
		NN_LOG_WRN("HUB_STATUS_ANNOUNCE build rv=%d", rv);
		return;
	}
	(void)proto_udp_send_mcast(frame, flen);
	NN_LOG_INF("HUB_STATUS_ANNOUNCE sent: online=%d", G.hub_online);
}

/* Send a D2G HUB_STATUS_QUERY to the hub via TCP.  Doubles as the
 * gateway's first frame after connect — the hub uses it to look up
 * the gateway in its DB and verify the outer signature. */
static void send_register_to_hub(void)
{
	const uint8_t *gw_id = gw_identity_get_id();
	if (!gw_id) {
		return;
	}
	uint8_t inner[2];
	nn_osal_put_le16(NN_PROTO_CMD_HUB_STATUS_QUERY, inner);

	uint8_t frame[NN_PROTO_OVERHEAD + GW_IDENTITY_ID_LEN + sizeof(inner)];
	int n = nn_proto_encode(NN_PROTO_TYPE_D2G,
				gw_id, GW_IDENTITY_ID_LEN,
				inner, sizeof(inner),
				gw_identity_sign, NULL,
				frame, sizeof(frame));
	if (n <= 0) {
		NN_LOG_WRN("register: encode rv=%d", n);
		return;
	}
	int rv = proto_tcp_enqueue(frame, (size_t)n);
	if (rv < 0) {
		NN_LOG_WRN("register: enqueue rv=%d", rv);
	} else {
		NN_LOG_INF("register frame enqueued (%d B) — hub will auth on receipt",
			n);
	}
}

void gw_commands_set_hub_online(bool online)
{
	if (G.hub_online == online) return;
	G.hub_online = online;
	send_hub_status_announce();
	if (online) {
		/* TCP just came up — introduce ourselves to the hub so it
		 * can authenticate us by our device_id + sig. */
		send_register_to_hub();
		/* Publish current Thread role/rloc16/mleid so the hub knows
		 * which gateway just came online and where we sit in the
		 * mesh.  Subsequent sends are driven by the periodic timer. */
		gw_thread_state_kick();
	}
}

void gw_commands_set_mesh_local(const struct in6_addr *addr)
{
	if (!addr) return;
	memcpy(&G.mesh_local, addr, sizeof(*addr));
}

/* ── D2G inner-cmd handler (hooked from proto_router) ─────────────────── */

int gw_commands_on_d2g(const struct nn_proto_view *view,
		       const struct in6_addr *src)
{
	if (!view || view->payload_size < 2) {
		return -EINVAL;
	}
	uint16_t cmd = nn_osal_get_le16(view->payload);
	switch (cmd) {
	case NN_PROTO_CMD_HUB_STATUS_QUERY: {
		/* Reply unicast to the requesting device with the current
		 * online flag.  device_id (= sender's id) is what's already
		 * in the inbound view. */
		uint8_t  args[HUBSTAT_ARGS_LEN] = { G.hub_online ? 1 : 0 };
		uint8_t  frame[NN_PROTO_OVERHEAD + HUBSTAT_ARGS_LEN + 2 +
			       PROTO_ROUTER_DEVICE_ID_MAX];
		size_t   flen = 0;
		int rv = build_g2d(NN_PROTO_CMD_HUB_STATUS_ANNOUNCE,
				   args, sizeof(args),
				   view->device_id, view->device_id_size,
				   frame, sizeof(frame), &flen);
		if (rv < 0) {
			NN_LOG_WRN("HUB_STATUS_QUERY reply build: %d", rv);
			return rv;
		}
		rv = proto_udp_send_unicast(src, UDP_PORT, frame, flen);
		if (rv < 0) {
			NN_LOG_WRN("HUB_STATUS_QUERY reply send: %d", rv);
			return rv;
		}
		return 0;
	}
	default:
		NN_LOG_DBG("unknown D2G cmd 0x%04x", cmd);
		return -ENOSYS;
	}
}

/* ── init ──────────────────────────────────────────────────────────────── */

int gw_commands_init(void)
{
	memset(&G, 0, sizeof(G));
	k_work_init_delayable(&G.hello_work, hello_timer);
	k_work_reschedule(&G.hello_work, K_SECONDS(HELLO_INTERVAL_S));
	NN_LOG_INF("gw_commands ready (HELLO every %d s on UDP/%d)",
		HELLO_INTERVAL_S, UDP_PORT);
	return 0;
}

/* ── broker glue (called from main once WiFi is up) ───────────────────── */

static void on_udp_rx(const uint8_t *buf, size_t len,
		      const struct in6_addr *src, uint16_t port, void *user)
{
	ARG_UNUSED(port); ARG_UNUSED(user);
	(void)proto_router_on_udp_rx(buf, len, src);
}

static void on_tcp_rx(const uint8_t *buf, size_t len, void *user)
{
	ARG_UNUSED(user);
	(void)proto_router_on_tcp_rx(buf, len);
}

/* TCP up/down poller — checks proto_tcp state every second and folds
 * the change into hub_online + emits the announce.  A future
 * enhancement could replace this poller with a state-change callback
 * inside proto_tcp.c. */
static void tcp_state_poll(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_tcp_state_work, tcp_state_poll);
static enum proto_tcp_state s_last_state = PROTO_TCP_DOWN;

static void tcp_state_poll(struct k_work *w)
{
	ARG_UNUSED(w);
	enum proto_tcp_state st = proto_tcp_get_state();
	if (st != s_last_state) {
		s_last_state = st;
		gw_commands_set_hub_online(st == PROTO_TCP_UP);
	}
	k_work_reschedule(&s_tcp_state_work, K_SECONDS(1));
}

void nn_proto_broker_start(void)
{
	(void)proto_router_init();

	static const struct proto_udp_config udp_cfg = {
		.port  = UDP_PORT,
		.on_rx = on_udp_rx,
	};
	(void)proto_udp_init(&udp_cfg);

	const char *hub_mdns = gw_provision_get_hub_mdns();
	static struct proto_tcp_config tcp_cfg;
	tcp_cfg.hub_hostname = hub_mdns ? hub_mdns
					: CONFIG_NN_PROTO_HUB_HOSTNAME;
	tcp_cfg.hub_port     = CONFIG_NN_PROTO_HUB_PORT;
	tcp_cfg.on_rx        = on_tcp_rx;
	(void)proto_tcp_init(&tcp_cfg);

	(void)gw_commands_init();
	gw_thread_state_init();
	k_work_reschedule(&s_tcp_state_work, K_SECONDS(1));
}
