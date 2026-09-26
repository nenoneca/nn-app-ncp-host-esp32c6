/* SPDX-License-Identifier: Apache-2.0 */
/*
 * proto_tcp — gateway-side TCP transport for the nn_proto wire format.
 *
 *   - Maintains a single TCP connection to the hub.
 *   - Resolves the hub via mDNS (CONFIG_NN_PROTO_HUB_HOSTNAME, override
 *     at runtime with `gw hub <addr>`) and connects to a fixed port.
 *   - Exponential backoff while disconnected: starts at
 *     CONFIG_NN_PROTO_RECONNECT_INITIAL_MS, doubles up to
 *     CONFIG_NN_PROTO_RECONNECT_MAX_MS.
 *   - One ring buffer holds outgoing frames awaiting send.
 *   - One worker thread handles connect / send / recv.
 *   - Inbound frames go to a caller-registered handler.
 *
 * Phase 2.C scope: connection lifecycle + frame I/O.  Routing decisions,
 * gateway commands (HELLO, hub-status), and registration handshake are
 * layered on top in later phases.
 */

#ifndef PROTO_TCP_H_
#define PROTO_TCP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <nn_osal/osal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* States the TCP transport can be in.  Visible via `gw status`. */
enum proto_tcp_state {
	PROTO_TCP_DOWN = 0,    /* not connected, backing off */
	PROTO_TCP_CONNECTING,  /* connect() / mDNS resolve in flight */
	PROTO_TCP_UP,          /* connected, frames flowing */
};

/* Inbound frame handler.  buf points to the full frame bytes
 * (header + device_id + payload + sig), len is the frame size.  The
 * buffer is owned by proto_tcp; the handler MUST copy any bytes it
 * needs to retain. */
typedef void (*proto_tcp_rx_fn)(const uint8_t *buf, size_t len, void *user);

struct proto_tcp_config {
	const char     *hub_hostname;   /* mDNS hostname, e.g. "nn-hub.local" */
	uint16_t        hub_port;       /* TCP port on hub */
	proto_tcp_rx_fn on_rx;          /* called from worker thread */
	void           *on_rx_user;
};

/* Initialize the transport and start the worker thread. */
int proto_tcp_init(const struct proto_tcp_config *cfg);

/* Override the hub hostname at runtime (used by `gw hub <addr>` shell).
 * Triggers a reconnect.  Pass NULL to revert to the Kconfig default. */
int proto_tcp_set_hub_hostname(const char *hostname);

/* Enqueue a complete frame for transmission.  The bytes are copied
 * into the ring buffer.  Drops on full and returns -ENOMEM (callers
 * are expected to retry on their own timer). */
int proto_tcp_enqueue(const uint8_t *frame, size_t len);

/* Snapshot of the current connection state. */
enum proto_tcp_state proto_tcp_get_state(void);

/* Counters since boot.  All best-effort; not atomic across fields. */
struct proto_tcp_stats {
	uint32_t connects;          /* successful TCP connects */
	uint32_t connect_failures;
	uint32_t disconnects;
	uint32_t tx_frames;
	uint32_t tx_bytes;
	uint32_t tx_drops_full;     /* enqueue refused, ring full */
	uint32_t tx_drops_socket;   /* socket-level write failure */
	uint32_t rx_frames;
	uint32_t rx_bytes;
	uint32_t rx_drops_oversize; /* frame > MTU was discarded */
	uint32_t rx_drops_bad;      /* parse / magic / pkt_size failure */
};

void proto_tcp_get_stats(struct proto_tcp_stats *out);

#ifdef __cplusplus
}
#endif

#endif /* PROTO_TCP_H_ */
