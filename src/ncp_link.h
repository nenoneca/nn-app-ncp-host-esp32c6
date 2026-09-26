/* SPDX-License-Identifier: Apache-2.0 */

/*
 * NCP link layer: UART1 + HDLC + Spinel request/reply.
 *
 * Responsibilities:
 *  - Own the UART1 device, install IRQ handler, pump RX bytes through
 *    the HDLC decoder.
 *  - Track outstanding requests by Spinel TID (1..15) and deliver the
 *    matching PROP_VALUE_IS reply to the caller.
 *  - Log unsolicited notifications (TID=0), incl. the NCP reset
 *    LAST_STATUS that arrives after the NCP boots.
 *
 * All blocking APIs are thread-safe and return after the reply (or
 * timeout).  Call from the shell or a worker thread — not from an ISR.
 */

#ifndef NCP_LINK_H_
#define NCP_LINK_H_

#include <stddef.h>
#include <stdint.h>

#include <nn_osal/osal.h>

/* Bring up UART + decoder + RX thread.  Returns 0 on success. */
int ncp_link_init(void);

/*
 * NCP reset signal.  When the NCP firmware boots (cold or after a
 * software reboot, e.g. post-OTA-swap), it emits an unsolicited
 * `PROP_VALUE_IS LAST_STATUS = reset:power-on/...` Spinel frame.  The
 * RX thread converts that into a one-shot semaphore signal.  Use:
 *
 *   ncp_link_arm_reset_signal();          // clear any prior signal
 *   ... trigger NCP reset (e.g. send FINALIZE) ...
 *   int rv = ncp_link_wait_reset(K_SECONDS(90));
 *   // rv == 0 means NCP came back; rv == -EAGAIN/-ETIMEDOUT means it didn't.
 *
 * Faster + more reliable than polling NCP_VERSION every 1s during a
 * MCUboot swap-scratch window.
 */
void ncp_link_arm_reset_signal(void);
int  ncp_link_wait_reset(k_timeout_t timeout);

/*
 * Quiet mode — when on, ncp_netif drops outbound STREAM_NET frames so
 * we don't pile up bytes in NCP's UART1 RX FIFO while it's busy with
 * MCUboot swap (no Spinel decoder running on the NCP side).  Without
 * this, the NCP's HDLC framer comes up post-swap into a UART buffer
 * full of partial frames, never resyncs, and the unsolicited
 * `reset:power-on` Spinel frame the new image emits gets eaten.
 *
 * The OTA's own BLOCK/FINALIZE/CONFIRM sends go through ncp_link_set_raw
 * directly and bypass this check (they'd be moot during the quiet
 * window anyway since the NCP isn't listening).
 *
 * Auto-clears when ncp_link_wait_reset returns 0 (reset signal arrived).
 */
void ncp_link_set_quiet_for_ota(bool quiet);
bool ncp_link_is_quiet_for_ota(void);

/*
 * Issue a PROP_VALUE_GET and wait for the matching PROP_VALUE_IS
 * reply.  Copies up to *out_len bytes of the value payload into
 * out_buf, then writes the actual length back to *out_len.
 *
 * Returns:
 *   0        on success
 *  -ETIMEDOUT if no reply within timeout
 *  -EIO      if NCP sent LAST_STATUS error instead
 *  -ENOMEM   if no TID slot available
 */
int ncp_link_get(uint32_t prop,
		 uint8_t *out_buf, size_t *out_len,
		 k_timeout_t timeout);

/*
 * Issue a PROP_VALUE_SET with `payload` as the pre-packed value.  Waits
 * for the matching PROP_VALUE_IS confirmation.  Returns 0 on success;
 * on NCP LAST_STATUS error, returns -EIO and sets *out_last_status (if
 * non-NULL) to the Spinel status code.
 */
int ncp_link_set_raw(uint32_t prop,
		     const uint8_t *payload, size_t payload_len,
		     uint32_t *out_last_status,
		     k_timeout_t timeout);

/*
 * PROP_VALUE_INSERT / PROP_VALUE_REMOVE — for list-typed properties
 * like IPV6_ADDRESS_TABLE, THREAD_OFF_MESH_ROUTES, THREAD_ON_MESH_NETS.
 */
int ncp_link_insert_raw(uint32_t prop,
			const uint8_t *payload, size_t payload_len,
			uint32_t *out_last_status,
			k_timeout_t timeout);

int ncp_link_remove_raw(uint32_t prop,
			const uint8_t *payload, size_t payload_len,
			uint32_t *out_last_status,
			k_timeout_t timeout);

/* Convenience wrappers over set_raw. */
int ncp_link_set_bool(uint32_t prop, bool v, k_timeout_t to);
int ncp_link_set_u8(uint32_t prop, uint8_t v, k_timeout_t to);
int ncp_link_set_u16(uint32_t prop, uint16_t v, k_timeout_t to);

/*
 * Send a UDP payload to the NCP-side Border Agent via Spinel
 * UDP_FORWARD_STREAM.  `remote_ip6` is the 16-byte commissioner address
 * (IPv4 commissioners are wrapped as IPv4-mapped IPv6, ::ffff:a.b.c.d).
 */
int ncp_link_udp_forward_tx(const uint8_t *payload, size_t payload_len,
			    uint16_t remote_port,
			    const uint8_t remote_ip6[16],
			    uint16_t local_port);

/*
 * Register a handler for UDP_FORWARD_STREAM packets coming FROM the NCP
 * (BA replies to a commissioner).  Called once at init; the handler
 * runs on the Spinel RX thread.
 */
typedef void (*ncp_link_udp_fwd_cb_t)(const uint8_t *payload, size_t len,
				      uint16_t remote_port,
				      const uint8_t remote_ip6[16],
				      uint16_t local_port);

void ncp_link_set_udp_fwd_cb(ncp_link_udp_fwd_cb_t cb);

/* Link statistics for `ncp stats`. */
struct ncp_link_stats {
	uint32_t rx_frames;
	uint32_t rx_bytes;
	uint32_t tx_frames;
	uint32_t tx_bytes;
	uint32_t rx_bad_fcs;
	uint32_t rx_unsolicited;
};

void ncp_link_stats_get(struct ncp_link_stats *out);

#endif /* NCP_LINK_H_ */
