/* SPDX-License-Identifier: Apache-2.0 */

#include "ncp_link.h"
#include "hdlc.h"
#include "ncp_netif.h"
#include "spinel.h"

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/ring_buffer.h>

#include <nn_osal/osal.h>

NN_OSAL_LOG_MODULE(ncp_link);

#define NCP_UART_NODE   DT_ALIAS(ncp_uart)

#if !DT_NODE_EXISTS(NCP_UART_NODE)
#error "Devicetree alias 'ncp-uart' is not defined (expected UART1)."
#endif

#define RX_RING_SZ   1024
#define TX_BUF_SZ    3072  /* enough for escaped 1280-byte STREAM_NET */

/* 15 Spinel request TIDs (1..15; 0 is reserved for unsolicited). */
#define MAX_TIDS     15

struct tid_slot {
	struct k_sem  done;
	uint8_t      *out_buf;
	size_t        out_cap;
	size_t        out_len;
	int           status;           /* 0 or negative errno */
	uint32_t      last_status_code; /* Spinel LAST_STATUS code if status==-EIO */
	bool          in_use;
};

static nn_osal_uart_t       s_uart;
static nn_osal_uart_t      *ncp_uart;   /* points to s_uart once init runs */

static struct hdlc_decoder  hdlc;
static uint8_t              rx_ring_buf[RX_RING_SZ];
static struct ring_buf      rx_ring;

static struct tid_slot      tids[MAX_TIDS + 1]; /* index by tid, 1..15 */
static struct k_mutex       tid_lock;
static uint8_t              next_tid = 1;

static struct ncp_link_stats stats;
static struct k_mutex        stats_lock;
static struct k_mutex        tx_lock;
static ncp_link_udp_fwd_cb_t udp_fwd_cb;

static K_THREAD_STACK_DEFINE(rx_thread_stack, 2048);
static struct k_thread       rx_thread_data;

/* ---- UART IRQ: drain RX into ring buffer, push TX from ring buffer ---- */

static void uart_irq_cb(nn_osal_uart_t *uart, void *user)
{
	(void)user;

	while (nn_osal_uart_irq_update(uart) &&
	       nn_osal_uart_irq_is_pending(uart)) {
		if (nn_osal_uart_irq_rx_ready(uart)) {
			uint8_t buf[64];
			int n = nn_osal_uart_fifo_read(uart, buf, sizeof(buf));
			if (n > 0) {
				uint32_t put = ring_buf_put(&rx_ring, buf, (uint32_t)n);
				if (put < (uint32_t)n) {
					NN_LOG_WRN("rx ring overflow, dropped %u",
						(unsigned)((uint32_t)n - put));
				}
			}
		}
	}
}

/* ---- Frame callback: parse Spinel and route ---- */

static void dispatch_response(uint8_t tid, const struct spinel_frame *f)
{
	if (tid < 1 || tid > MAX_TIDS) {
		return;
	}

	k_mutex_lock(&tid_lock, K_FOREVER);
	struct tid_slot *s = &tids[tid];
	if (!s->in_use) {
		k_mutex_unlock(&tid_lock);
		NN_LOG_DBG("reply for unowned tid=%u", tid);
		return;
	}

	if (!f->has_prop) {
		s->status = -EIO;
	} else if (f->prop == SPINEL_PROP_LAST_STATUS) {
		uint32_t code = 0;
		(void)spinel_unpack_uint(f->value, f->value_len, &code);
		s->last_status_code = code;
		if (code == SPINEL_STATUS_OK) {
			s->out_len = 0;
			s->status = 0;
		} else {
			NN_LOG_WRN("NCP last-status for tid=%u: %u (%s)",
				tid, code, spinel_status_str(code));
			s->status = -EIO;
		}
	} else {
		size_t n = MIN(f->value_len, s->out_cap);
		if (s->out_buf && n > 0) {
			memcpy(s->out_buf, f->value, n);
		}
		s->out_len = n;
		s->status = 0;
	}

	k_sem_give(&s->done);
	k_mutex_unlock(&tid_lock);
}

/* One-shot signal for "NCP just rebooted".  See header for usage. */
static K_SEM_DEFINE(s_ncp_reset_sem, 0, 1);

/* Quiet-mode flag — see ncp_link.h.  atomic_t for lock-free read on
 * the ncp_netif tx hot path. */
static atomic_t s_quiet_for_ota = ATOMIC_INIT(0);

void ncp_link_arm_reset_signal(void)
{
	k_sem_reset(&s_ncp_reset_sem);
}

int ncp_link_wait_reset(k_timeout_t timeout)
{
	int rv = k_sem_take(&s_ncp_reset_sem, timeout);
	if (rv == 0) {
		/* NCP came back — auto-clear quiet so normal traffic
		 * resumes without the caller having to remember. */
		atomic_set(&s_quiet_for_ota, 0);
	}
	return rv;
}

void ncp_link_set_quiet_for_ota(bool quiet)
{
	atomic_set(&s_quiet_for_ota, quiet ? 1 : 0);
}

bool ncp_link_is_quiet_for_ota(void)
{
	return atomic_get(&s_quiet_for_ota) != 0;
}

static void handle_unsolicited(const struct spinel_frame *f)
{
	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.rx_unsolicited++;
	k_mutex_unlock(&stats_lock);

	if (f->cmd == SPINEL_CMD_PROP_VALUE_IS && f->has_prop) {
		switch (f->prop) {
		case SPINEL_PROP_LAST_STATUS: {
			uint32_t code = 0;
			(void)spinel_unpack_uint(f->value, f->value_len, &code);
			NN_LOG_INF("NCP unsolicited: last-status=%u (%s)",
				code, spinel_status_str(code));
			/* SPINEL_STATUS_RESET_* covers 112..127 — any of these
			 * means the NCP just booted/rebooted.  Wake any
			 * waiter on the reset semaphore. */
			if (code >= 112 && code <= 127) {
				k_sem_give(&s_ncp_reset_sem);
			}
			break;
		}
		case SPINEL_PROP_STREAM_NET:
			ncp_netif_rx_stream_net(f->value, f->value_len);
			break;
		case SPINEL_PROP_THREAD_UDP_FORWARD_STREAM:
			if (IS_ENABLED(CONFIG_NCP_LINK_LOG_UDP_FORWARD)) {
				printk("ufwd_rx: UDP_FORWARD_STREAM len=%zu\n",
				       f->value_len);
			}
			if (udp_fwd_cb) {
				/* `dS6S` layout: len-prefixed payload + u16 le
				 * remote port + 16B IPv6 + u16 le local port */
				if (f->value_len < 2) break;
				size_t plen = (size_t)f->value[0] |
					      ((size_t)f->value[1] << 8);
				if (f->value_len < 2 + plen + 2 + 16 + 2) break;
				const uint8_t *p = f->value + 2;
				uint16_t rport = (uint16_t)p[plen] |
						 ((uint16_t)p[plen + 1] << 8);
				const uint8_t *rip6 = p + plen + 2;
				uint16_t lport = (uint16_t)rip6[16] |
						 ((uint16_t)rip6[17] << 8);
				udp_fwd_cb(p, plen, rport, rip6, lport);
			}
			break;
		default:
			NN_LOG_DBG("unsolicited IS prop=%u len=%zu",
				f->prop, f->value_len);
			break;
		}
	} else {
		NN_LOG_DBG("unsolicited cmd=%u prop=%u len=%zu",
			f->cmd, f->prop, f->value_len);
	}
}

static void on_hdlc_frame(const uint8_t *payload, size_t len, void *user)
{
	ARG_UNUSED(user);

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.rx_frames++;
	stats.rx_bytes += (uint32_t)len;
	k_mutex_unlock(&stats_lock);

	struct spinel_frame f = {0};
	if (spinel_parse(payload, len, &f) < 0) {
		NN_LOG_WRN("bad spinel frame (len=%zu)", len);
		return;
	}

	if (f.tid == 0) {
		handle_unsolicited(&f);
	} else {
		dispatch_response(f.tid, &f);
	}
}

/* ---- RX thread ---- */

static void rx_thread_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	for (;;) {
		uint8_t buf[128];
		uint32_t n = ring_buf_get(&rx_ring, buf, sizeof(buf));
		if (n == 0) {
			nn_osal_sleep_ms(2);
			continue;
		}
		hdlc_decode(&hdlc, buf, (size_t)n);
	}
}

/* ---- TX ---- */

static int send_spinel(const uint8_t *payload, size_t payload_len)
{
	/* Hold tx_lock across encode+write so concurrent callers don't
	 * interleave bytes on the wire.  The wire buffer is large enough
	 * for a fully-escaped max-MTU STREAM_NET frame. */
	static uint8_t wire[TX_BUF_SZ];

	k_mutex_lock(&tx_lock, K_FOREVER);

	int n = hdlc_encode(payload, payload_len, wire, sizeof(wire));
	if (n < 0) {
		k_mutex_unlock(&tx_lock);
		NN_LOG_ERR("hdlc_encode: frame too large (%zu)", payload_len);
		return -EMSGSIZE;
	}

	for (int i = 0; i < n; i++) {
		nn_osal_uart_poll_out(ncp_uart, wire[i]);
	}

	k_mutex_unlock(&tx_lock);

	k_mutex_lock(&stats_lock, K_FOREVER);
	stats.tx_frames++;
	stats.tx_bytes += (uint32_t)n;
	k_mutex_unlock(&stats_lock);
	return 0;
}

/* ---- Public API ---- */

static int reserve_tid(struct tid_slot **out_slot, uint8_t *out_tid,
		       uint8_t *out_buf, size_t out_cap)
{
	k_mutex_lock(&tid_lock, K_FOREVER);

	for (int i = 0; i < MAX_TIDS; i++) {
		uint8_t t = (uint8_t)(((next_tid - 1 + i) % MAX_TIDS) + 1);
		struct tid_slot *s = &tids[t];
		if (!s->in_use) {
			s->in_use = true;
			s->out_buf = out_buf;
			s->out_cap = out_cap;
			s->out_len = 0;
			s->status = -ETIMEDOUT;
			s->last_status_code = 0;
			k_sem_reset(&s->done);
			next_tid = (uint8_t)((t % MAX_TIDS) + 1);
			*out_slot = s;
			*out_tid = t;
			k_mutex_unlock(&tid_lock);
			return 0;
		}
	}

	k_mutex_unlock(&tid_lock);
	return -ENOMEM;
}

static void release_tid(struct tid_slot *s)
{
	k_mutex_lock(&tid_lock, K_FOREVER);
	s->in_use = false;
	s->out_buf = NULL;
	s->out_cap = 0;
	k_mutex_unlock(&tid_lock);
}

int ncp_link_get(uint32_t prop,
		 uint8_t *out_buf, size_t *out_len,
		 k_timeout_t timeout)
{
	if (!out_len) {
		return -EINVAL;
	}

	struct tid_slot *slot;
	uint8_t tid;
	int rv = reserve_tid(&slot, &tid, out_buf, *out_len);
	if (rv < 0) {
		*out_len = 0;
		return rv;
	}

	uint8_t frame[32];
	int n = spinel_build_get(frame, sizeof(frame), tid, prop);
	if (n < 0) {
		release_tid(slot);
		*out_len = 0;
		return -EMSGSIZE;
	}

	rv = send_spinel(frame, (size_t)n);
	if (rv < 0) {
		release_tid(slot);
		*out_len = 0;
		return rv;
	}

	if (k_sem_take(&slot->done, timeout) != 0) {
		release_tid(slot);
		*out_len = 0;
		return -ETIMEDOUT;
	}

	int status = slot->status;
	*out_len = slot->out_len;
	release_tid(slot);
	return status;
}

static int link_cmd_raw(uint32_t cmd, uint32_t prop,
			const uint8_t *payload, size_t payload_len,
			uint32_t *out_last_status,
			k_timeout_t timeout)
{
	struct tid_slot *slot;
	uint8_t tid;
	int rv = reserve_tid(&slot, &tid, NULL, 0);
	if (rv < 0) {
		return rv;
	}

	/* Big enough for header(1) + cmd(1) + prop(1-2) + 2-byte length +
	 * 1280-byte Thread MTU + slack.  Recursive tx_lock protects the
	 * static buffer and the subsequent wire write as one unit. */
	static uint8_t frame[1300];
	k_mutex_lock(&tx_lock, K_FOREVER);

	int n = spinel_build_cmd(frame, sizeof(frame), tid, cmd, prop,
				 payload, payload_len);
	if (n < 0) {
		k_mutex_unlock(&tx_lock);
		release_tid(slot);
		return -EMSGSIZE;
	}

	rv = send_spinel(frame, (size_t)n);
	k_mutex_unlock(&tx_lock);
	if (rv < 0) {
		release_tid(slot);
		return rv;
	}

	if (k_sem_take(&slot->done, timeout) != 0) {
		release_tid(slot);
		return -ETIMEDOUT;
	}

	int status = slot->status;
	if (out_last_status) {
		*out_last_status = slot->last_status_code;
	}
	release_tid(slot);
	return status;
}

int ncp_link_set_raw(uint32_t prop,
		     const uint8_t *payload, size_t payload_len,
		     uint32_t *out_last_status,
		     k_timeout_t timeout)
{
	return link_cmd_raw(SPINEL_CMD_PROP_VALUE_SET, prop,
			    payload, payload_len, out_last_status, timeout);
}

int ncp_link_insert_raw(uint32_t prop,
			const uint8_t *payload, size_t payload_len,
			uint32_t *out_last_status,
			k_timeout_t timeout)
{
	return link_cmd_raw(SPINEL_CMD_PROP_VALUE_INSERT, prop,
			    payload, payload_len, out_last_status, timeout);
}

int ncp_link_remove_raw(uint32_t prop,
			const uint8_t *payload, size_t payload_len,
			uint32_t *out_last_status,
			k_timeout_t timeout)
{
	return link_cmd_raw(SPINEL_CMD_PROP_VALUE_REMOVE, prop,
			    payload, payload_len, out_last_status, timeout);
}

int ncp_link_set_bool(uint32_t prop, bool v, k_timeout_t to)
{
	uint8_t b = v ? 1 : 0;
	return ncp_link_set_raw(prop, &b, 1, NULL, to);
}

int ncp_link_set_u8(uint32_t prop, uint8_t v, k_timeout_t to)
{
	return ncp_link_set_raw(prop, &v, 1, NULL, to);
}

int ncp_link_set_u16(uint32_t prop, uint16_t v, k_timeout_t to)
{
	uint8_t buf[2] = { (uint8_t)(v & 0xff), (uint8_t)(v >> 8) };
	return ncp_link_set_raw(prop, buf, 2, NULL, to);
}

void ncp_link_stats_get(struct ncp_link_stats *out)
{
	k_mutex_lock(&stats_lock, K_FOREVER);
	*out = stats;
	k_mutex_unlock(&stats_lock);
}

void ncp_link_set_udp_fwd_cb(ncp_link_udp_fwd_cb_t cb)
{
	udp_fwd_cb = cb;
}

int ncp_link_udp_forward_tx(const uint8_t *payload, size_t payload_len,
			    uint16_t remote_port,
			    const uint8_t remote_ip6[16],
			    uint16_t local_port)
{
	if (payload_len > 1024) {
		return -EMSGSIZE;
	}

	static uint8_t body[1100];
	size_t n = 0;
	body[n++] = (uint8_t)(payload_len & 0xff);
	body[n++] = (uint8_t)(payload_len >> 8);
	memcpy(body + n, payload, payload_len);
	n += payload_len;
	body[n++] = (uint8_t)(remote_port & 0xff);
	body[n++] = (uint8_t)(remote_port >> 8);
	memcpy(body + n, remote_ip6, 16);
	n += 16;
	body[n++] = (uint8_t)(local_port & 0xff);
	body[n++] = (uint8_t)(local_port >> 8);

	uint32_t ls = 0;
	int rv = ncp_link_set_raw(SPINEL_PROP_THREAD_UDP_FORWARD_STREAM,
				  body, n, &ls, K_MSEC(500));
	if (IS_ENABLED(CONFIG_NCP_LINK_LOG_UDP_FORWARD)) {
		printk("ufwd_tx: pl=%zu rport=%u lport=%u rv=%d ls=%u\n",
		       payload_len, remote_port, local_port, rv, ls);
	}
	return rv;
}

int ncp_link_init(void)
{
	/* The DT_ALIAS+DEVICE_DT_GET pair stays here — it's the
	 * compile-time bridge from the board's devicetree into the
	 * runtime nn_osal_uart_t.  Other ncp_host code references the
	 * UART only as nn_osal_uart_get("ncp"). */
	const struct device *uart_dev = DEVICE_DT_GET(NCP_UART_NODE);
	if (!device_is_ready(uart_dev)) {
		NN_LOG_ERR("ncp-uart device not ready");
		return -ENODEV;
	}
	s_uart.dev     = uart_dev;
	s_uart.user_cb = NULL;
	s_uart.user_data = NULL;
	ncp_uart = &s_uart;
	nn_osal_uart_register("ncp", ncp_uart);

	ring_buf_init(&rx_ring, sizeof(rx_ring_buf), rx_ring_buf);
	hdlc_decoder_init(&hdlc, on_hdlc_frame, NULL);

	k_mutex_init(&tid_lock);
	k_mutex_init(&stats_lock);
	k_mutex_init(&tx_lock);
	for (int i = 0; i <= MAX_TIDS; i++) {
		k_sem_init(&tids[i].done, 0, 1);
	}

	nn_osal_uart_irq_callback_set(ncp_uart, uart_irq_cb, NULL);
	nn_osal_uart_irq_rx_enable(ncp_uart);

	k_thread_create(&rx_thread_data, rx_thread_stack,
			K_THREAD_STACK_SIZEOF(rx_thread_stack),
			rx_thread_fn, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&rx_thread_data, "ncp_rx");

	NN_LOG_INF("ncp link up on %s", s_uart.dev->name);
	return 0;
}
