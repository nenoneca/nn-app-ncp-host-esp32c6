/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>


#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>

#include "proto_router.h"
#include "proto_tcp.h"
#include "proto_udp.h"

NN_OSAL_LOG_MODULE(proto_router);

/* Forward declared in proto_router.h via shell.h shadow.  Pull in
 * properly here. */
struct shell;

#define UDP_PORT  CONFIG_NN_PROTO_UDP_PORT

/* Optional weak hook into the gateway-command layer (Phase 2.F).  When
 * the router gets a D2G frame, it can hand it off here for inner-cmd
 * dispatch.  Returns 0 if handled (no further forwarding), negative
 * otherwise.  Default impl does nothing. */
__weak int gw_commands_on_d2g(const struct nn_proto_view *view,
			      const struct in6_addr *src);
int gw_commands_on_d2g(const struct nn_proto_view *view,
		       const struct in6_addr *src)
{
	NN_OSAL_UNUSED(view);
	NN_OSAL_UNUSED(src);
	return -ENOSYS;
}

/* ── routing table ─────────────────────────────────────────────────────── */

struct route_entry {
	uint8_t          device_id[PROTO_ROUTER_DEVICE_ID_MAX];
	uint16_t         did_size;
	struct in6_addr  addr;
	uint64_t         last_seen_ms;  /* nn_osal_uptime_ms() at last update */
	bool             used;
};

static struct {
	struct route_entry         table[PROTO_ROUTER_TABLE_SIZE];
	struct k_mutex             lock;
	struct proto_router_stats  stats;
} R;

static int find_entry(const uint8_t *did, uint16_t did_size)
{
	for (int i = 0; i < PROTO_ROUTER_TABLE_SIZE; i++) {
		if (R.table[i].used &&
		    R.table[i].did_size == did_size &&
		    memcmp(R.table[i].device_id, did, did_size) == 0) {
			return i;
		}
	}
	return -1;
}

static int find_lru_or_free(void)
{
	int      best = -1;
	uint64_t oldest = UINT64_MAX;
	for (int i = 0; i < PROTO_ROUTER_TABLE_SIZE; i++) {
		if (!R.table[i].used) {
			return i;
		}
		if (R.table[i].last_seen_ms < oldest) {
			oldest = R.table[i].last_seen_ms;
			best = i;
		}
	}
	return best;
}

int proto_router_remember(const uint8_t *device_id, uint16_t did_size,
			  const struct in6_addr *addr)
{
	if (!device_id || !addr || did_size == 0 ||
	    did_size > PROTO_ROUTER_DEVICE_ID_MAX) {
		return -EINVAL;
	}
	k_mutex_lock(&R.lock, K_FOREVER);
	int idx = find_entry(device_id, did_size);
	if (idx < 0) {
		idx = find_lru_or_free();
		if (R.table[idx].used) {
			R.stats.table_evictions++;
		} else {
			R.stats.table_inserts++;
		}
	}
	memset(&R.table[idx], 0, sizeof(R.table[idx]));
	memcpy(R.table[idx].device_id, device_id, did_size);
	R.table[idx].did_size      = did_size;
	memcpy(&R.table[idx].addr, addr, sizeof(*addr));
	R.table[idx].last_seen_ms  = nn_osal_uptime_ms();
	R.table[idx].used          = true;
	k_mutex_unlock(&R.lock);
	return 0;
}

int proto_router_lookup(const uint8_t *device_id, uint16_t did_size,
			struct in6_addr *out_addr)
{
	if (!device_id || did_size == 0 || did_size > PROTO_ROUTER_DEVICE_ID_MAX) {
		return -EINVAL;
	}
	k_mutex_lock(&R.lock, K_FOREVER);
	int idx = find_entry(device_id, did_size);
	if (idx < 0) {
		k_mutex_unlock(&R.lock);
		return -ENOENT;
	}
	if (out_addr) {
		memcpy(out_addr, &R.table[idx].addr, sizeof(*out_addr));
	}
	R.table[idx].last_seen_ms = nn_osal_uptime_ms();
	k_mutex_unlock(&R.lock);
	return 0;
}

void proto_router_dump_table(nn_osal_shell_ctx_t *sh)
{
	k_mutex_lock(&R.lock, K_FOREVER);
	for (int i = 0; i < PROTO_ROUTER_TABLE_SIZE; i++) {
		if (!R.table[i].used) continue;
		char ip[NET_IPV6_ADDR_LEN];
		net_addr_ntop(AF_INET6, &R.table[i].addr, ip, sizeof(ip));
		nn_osal_shell_print(sh, "  [%2d] did=%u-byte addr=%s",
			    i, R.table[i].did_size, ip);
	}
	k_mutex_unlock(&R.lock);
}

void proto_router_get_stats(struct proto_router_stats *out)
{
	if (out) *out = R.stats;
}

/* ── dispatch ──────────────────────────────────────────────────────────── */

int proto_router_on_udp_rx(const uint8_t *frame, size_t len,
			   const struct in6_addr *src)
{
	struct nn_proto_view view;
	int rv = nn_proto_parse(frame, len, &view, NULL);
	if (rv != 0) {
		R.stats.drops_bad_type++;
		return rv;
	}

	/* Update routing table whenever a device speaks. */
	if (view.device_id_size > 0 &&
	    view.device_id_size <= PROTO_ROUTER_DEVICE_ID_MAX) {
		(void)proto_router_remember(view.device_id, view.device_id_size,
					    src);
	}

	switch (view.type) {
	case NN_PROTO_TYPE_D2H:
		R.stats.in_d2h++;
		if (proto_tcp_enqueue(frame, len) < 0) {
			R.stats.drops_tcp_enqueue++;
			return -ENOMEM;
		}
		R.stats.fwd_d2h_to_tcp++;
		return 0;

	case NN_PROTO_TYPE_D2G:
		R.stats.in_d2g++;
		/* Hand to gw commands; if not handled, drop silently. */
		if (gw_commands_on_d2g(&view, src) == 0) {
			return 0;
		}
		NN_LOG_DBG("D2G with unknown cmd; dropped");
		return 0;

	default:
		R.stats.drops_bad_type++;
		NN_LOG_WRN("unexpected type 0x%04x on UDP", view.type);
		return -EBADF;
	}
}

int proto_router_on_tcp_rx(const uint8_t *frame, size_t len)
{
	struct nn_proto_view view;
	int rv = nn_proto_parse(frame, len, &view, NULL);
	if (rv != 0) {
		R.stats.drops_bad_type++;
		return rv;
	}

	struct in6_addr dst;
	switch (view.type) {
	case NN_PROTO_TYPE_H2D:
		R.stats.in_h2d++;
		if (view.device_id_size == 0) {
			R.stats.drops_unknown_did++;
			return -EINVAL;
		}
		if (proto_router_lookup(view.device_id, view.device_id_size,
					&dst) < 0) {
			R.stats.drops_unknown_did++;
			NN_LOG_WRN("H2D: device_id not in routing table");
			return -EHOSTUNREACH;
		}
		if (proto_udp_send_unicast(&dst, UDP_PORT, frame, len) < 0) {
			R.stats.drops_udp_send++;
			return -EIO;
		}
		R.stats.fwd_h2d_to_udp++;
		return 0;

	case NN_PROTO_TYPE_G2D:
		/* Hub originating G2D for the gateway to relay verbatim. */
		R.stats.in_g2d++;
		if (view.device_id_size == 0) {
			if (proto_udp_send_mcast(frame, len) < 0) {
				R.stats.drops_udp_send++;
				return -EIO;
			}
			return 0;
		}
		if (proto_router_lookup(view.device_id, view.device_id_size,
					&dst) < 0) {
			R.stats.drops_unknown_did++;
			return -EHOSTUNREACH;
		}
		if (proto_udp_send_unicast(&dst, UDP_PORT, frame, len) < 0) {
			R.stats.drops_udp_send++;
			return -EIO;
		}
		return 0;

	default:
		R.stats.drops_bad_type++;
		NN_LOG_WRN("unexpected type 0x%04x on TCP", view.type);
		return -EBADF;
	}
}

/* ── init ──────────────────────────────────────────────────────────────── */

int proto_router_init(void)
{
	k_mutex_init(&R.lock);
	memset(R.table, 0, sizeof(R.table));
	return 0;
}
