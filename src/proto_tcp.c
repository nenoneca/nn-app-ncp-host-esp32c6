/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/net/socket.h>
#include <zephyr/sys/ring_buffer.h>

#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>

#include "proto_tcp.h"

NN_OSAL_LOG_MODULE(proto_tcp);

/* ── tunables ───────────────────────────────────────────────────────────── */

#define WORKER_STACK_SIZE     CONFIG_NN_PROTO_WORKER_STACK_SIZE
#define WORKER_PRIO           5
#define TX_RING_BYTES         CONFIG_NN_PROTO_TX_RING_BYTES
#define RX_BUF_BYTES          CONFIG_NN_PROTO_RX_BUF_BYTES
#define RECONNECT_INITIAL_MS  CONFIG_NN_PROTO_RECONNECT_INITIAL_MS
#define RECONNECT_MAX_MS      CONFIG_NN_PROTO_RECONNECT_MAX_MS
#define HOSTNAME_MAX          64

/* ── state ──────────────────────────────────────────────────────────────── */

static struct {
	struct proto_tcp_config cfg;
	char                    hostname[HOSTNAME_MAX];
	int                     fd;            /* TCP socket, -1 if down */
	enum proto_tcp_state    state;
	uint32_t                next_backoff_ms;
	struct proto_tcp_stats  stats;

	/* TX ring: byte-oriented, frames concatenated.  Each enqueue
	 * writes a 4-byte LE length prefix followed by the frame bytes
	 * so the worker can slice them back out. */
	struct ring_buf         tx_ring;
	uint8_t                 tx_storage[TX_RING_BYTES];
	struct k_sem            tx_sem;        /* signal the worker */

	/* RX assembly buffer: frames arrive as TCP byte stream; we
	 * accumulate up to one frame's worth and parse with nn_proto. */
	uint8_t                 rx_buf[RX_BUF_BYTES];
	size_t                  rx_len;        /* valid bytes in rx_buf */
} S;

K_THREAD_STACK_DEFINE(s_worker_stack, WORKER_STACK_SIZE);
static struct k_thread s_worker;

/* ── helpers ────────────────────────────────────────────────────────────── */

static void close_socket(void)
{
	if (S.fd >= 0) {
		zsock_close(S.fd);
		S.fd = -1;
		S.stats.disconnects++;
	}
	S.state = PROTO_TCP_DOWN;
}

static int try_connect(void)
{
	struct zsock_addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct zsock_addrinfo *result = NULL;

	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%u", S.cfg.hub_port);

	S.state = PROTO_TCP_CONNECTING;

	int rv = zsock_getaddrinfo(S.hostname, port_str, &hints, &result);
	if (rv != 0 || !result) {
		NN_LOG_WRN("getaddrinfo(%s) -> %d", S.hostname, rv);
		S.stats.connect_failures++;
		return -EHOSTUNREACH;
	}

	int fd = zsock_socket(result->ai_family, result->ai_socktype,
			      result->ai_protocol);
	if (fd < 0) {
		NN_LOG_ERR("socket: %d", errno);
		zsock_freeaddrinfo(result);
		S.stats.connect_failures++;
		return -errno;
	}

	/* Non-default 5 s connect timeout via SO_RCVTIMEO is fiddly on
	 * Zephyr; rely on TCP's own connect-retry behaviour. */
	rv = zsock_connect(fd, result->ai_addr, result->ai_addrlen);
	zsock_freeaddrinfo(result);
	if (rv < 0) {
		NN_LOG_WRN("connect(%s:%s): %d", S.hostname, port_str, errno);
		zsock_close(fd);
		S.stats.connect_failures++;
		return -errno;
	}

	S.fd = fd;
	S.state = PROTO_TCP_UP;
	S.next_backoff_ms = RECONNECT_INITIAL_MS;
	S.stats.connects++;
	NN_LOG_INF("TCP connected to %s:%s (fd=%d)", S.hostname, port_str, fd);
	return 0;
}

/* Drain pending frames from the TX ring to the socket.  Returns 0 on
 * success or -EIO on socket failure (caller must close).
 *
 * The temporary frame buffer is sized for the Thread MTU (≈1232 B
 * after IPv6/UDP overhead).  Anything larger is dropped at enqueue
 * time anyway since it can't traverse the device side. */
static uint8_t s_frame_buf[NN_PROTO_HEADER_FIXED + 1280 + NN_PROTO_SIG_LEN];

static int drain_tx(void)
{
	while (true) {
		uint8_t  len_hdr[4];
		uint32_t got = ring_buf_peek(&S.tx_ring, len_hdr, sizeof(len_hdr));
		if (got < sizeof(len_hdr)) {
			return 0;  /* nothing to send */
		}
		uint32_t flen = nn_osal_get_le32(len_hdr);
		if (flen > sizeof(s_frame_buf) - sizeof(len_hdr) ||
		    flen > TX_RING_BYTES - sizeof(len_hdr)) {
			NN_LOG_ERR("frame too large to drain: %u", flen);
			ring_buf_reset(&S.tx_ring);
			S.stats.tx_drops_socket++;
			return 0;
		}
		uint32_t total = sizeof(len_hdr) + flen;
		ring_buf_get(&S.tx_ring, s_frame_buf, total);

		const uint8_t *p = s_frame_buf + sizeof(len_hdr);
		size_t left = flen;
		while (left) {
			ssize_t n = zsock_send(S.fd, p, left, 0);
			if (n <= 0) {
				NN_LOG_WRN("send: rv=%zd errno=%d", n, errno);
				S.stats.tx_drops_socket++;
				return -EIO;
			}
			p    += n;
			left -= (size_t)n;
		}
		S.stats.tx_frames++;
		S.stats.tx_bytes += flen;
	}
}

/* Consume bytes from S.rx_buf, dispatching every complete frame to the
 * RX handler.  Returns 0 on success, -EIO on parse failure (caller
 * should close the socket). */
static int parse_rx_buf(void)
{
	while (true) {
		struct nn_proto_view view;
		size_t consumed = 0;
		int rv = nn_proto_parse(S.rx_buf, S.rx_len, &view, &consumed);
		if (rv == -ENOSPC) {
			return 0;  /* need more bytes */
		}
		if (rv != 0) {
			NN_LOG_WRN("nn_proto_parse: %d (rx_len=%zu)", rv, S.rx_len);
			S.stats.rx_drops_bad++;
			return -EIO;
		}

		S.stats.rx_frames++;
		S.stats.rx_bytes += consumed;
		if (S.cfg.on_rx) {
			S.cfg.on_rx(S.rx_buf, consumed, S.cfg.on_rx_user);
		}
		/* Shift remainder forward. */
		size_t remaining = S.rx_len - consumed;
		if (remaining) {
			memmove(S.rx_buf, S.rx_buf + consumed, remaining);
		}
		S.rx_len = remaining;
	}
}

static int recv_some(void)
{
	if (S.rx_len >= sizeof(S.rx_buf)) {
		NN_LOG_ERR("rx_buf full (%zu B); dropping connection", S.rx_len);
		S.stats.rx_drops_oversize++;
		return -EIO;
	}

	struct zsock_pollfd pfd = { .fd = S.fd, .events = ZSOCK_POLLIN };
	int rv = zsock_poll(&pfd, 1, 100 /* ms */);
	if (rv < 0) {
		return -errno;
	}
	if (rv == 0) {
		return 0;  /* timeout, no data */
	}
	if (pfd.revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP)) {
		NN_LOG_WRN("poll: revents=0x%x", pfd.revents);
		return -EIO;
	}

	ssize_t n = zsock_recv(S.fd, S.rx_buf + S.rx_len,
			       sizeof(S.rx_buf) - S.rx_len, 0);
	if (n < 0) {
		NN_LOG_WRN("recv: errno=%d", errno);
		return -EIO;
	}
	if (n == 0) {
		NN_LOG_INF("peer closed");
		return -EIO;
	}
	S.rx_len += (size_t)n;
	return parse_rx_buf();
}

/* ── worker thread ─────────────────────────────────────────────────────── */

static void worker_main(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	/* Initial back-off so we don't hammer mDNS before WiFi is up. */
	nn_osal_sleep_ms(2000);

	while (true) {
		if (S.state != PROTO_TCP_UP) {
			int rv = try_connect();
			if (rv < 0) {
				uint32_t wait = S.next_backoff_ms;
				NN_LOG_INF("backoff %u ms", wait);
				nn_osal_sleep_ms(wait);
				S.next_backoff_ms = MIN(S.next_backoff_ms * 2u,
							(uint32_t)RECONNECT_MAX_MS);
				continue;
			}
			S.rx_len = 0;
		}

		/* Service TX (drain ring) and RX (poll for bytes). */
		int rv = drain_tx();
		if (rv < 0) {
			close_socket();
			continue;
		}
		rv = recv_some();
		if (rv < 0) {
			close_socket();
			continue;
		}

		/* If TX queue has new entries, the sem will fire and we'll
		 * loop immediately.  Otherwise short sleep so RX poll has a
		 * chance to tick again. */
		k_sem_take(&S.tx_sem, K_MSEC(50));
	}
}

/* ── public API ─────────────────────────────────────────────────────────── */

int proto_tcp_init(const struct proto_tcp_config *cfg)
{
	if (!cfg || !cfg->hub_hostname || !cfg->hub_port) {
		return -EINVAL;
	}
	memset(&S, 0, sizeof(S));
	S.cfg = *cfg;
	S.fd  = -1;
	S.next_backoff_ms = RECONNECT_INITIAL_MS;
	strncpy(S.hostname, cfg->hub_hostname, sizeof(S.hostname) - 1);

	ring_buf_init(&S.tx_ring, sizeof(S.tx_storage), S.tx_storage);
	k_sem_init(&S.tx_sem, 0, 1);

	k_thread_create(&s_worker, s_worker_stack,
			K_THREAD_STACK_SIZEOF(s_worker_stack),
			worker_main, NULL, NULL, NULL,
			WORKER_PRIO, 0, K_NO_WAIT);
	k_thread_name_set(&s_worker, "proto_tcp");

	NN_LOG_INF("proto_tcp init: hub=%s:%u", S.hostname, S.cfg.hub_port);
	return 0;
}

int proto_tcp_set_hub_hostname(const char *hostname)
{
	const char *new_h = hostname && hostname[0] ?
			    hostname : S.cfg.hub_hostname;
	if (strncmp(new_h, S.hostname, sizeof(S.hostname)) == 0) {
		return 0;  /* unchanged */
	}
	strncpy(S.hostname, new_h, sizeof(S.hostname) - 1);
	S.hostname[sizeof(S.hostname) - 1] = 0;
	NN_LOG_INF("hub hostname → %s; forcing reconnect", S.hostname);
	close_socket();
	S.next_backoff_ms = RECONNECT_INITIAL_MS;
	k_sem_give(&S.tx_sem);
	return 0;
}

int proto_tcp_enqueue(const uint8_t *frame, size_t len)
{
	if (!frame || len == 0 || len > 0xFFFFFFFFu) {
		return -EINVAL;
	}
	uint8_t hdr[4];
	nn_osal_put_le32((uint32_t)len, hdr);

	/* Need atomic-ish "write hdr then frame, or nothing".  Use the
	 * standard ring_buf "two writes" pattern and hope nobody else is
	 * a producer.  TX is single-producer (callers serialize via
	 * normal program flow); the worker is the single consumer. */
	uint32_t free = ring_buf_space_get(&S.tx_ring);
	if (free < (uint32_t)(sizeof(hdr) + len)) {
		S.stats.tx_drops_full++;
		return -ENOMEM;
	}
	ring_buf_put(&S.tx_ring, hdr, sizeof(hdr));
	ring_buf_put(&S.tx_ring, frame, len);
	k_sem_give(&S.tx_sem);
	return 0;
}

enum proto_tcp_state proto_tcp_get_state(void)
{
	return S.state;
}

void proto_tcp_get_stats(struct proto_tcp_stats *out)
{
	if (out) {
		*out = S.stats;
	}
}
