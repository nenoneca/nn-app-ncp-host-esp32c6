/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ncp_ota_client — host side of the NCP OTA relay.
 *
 *   1. Pull manifest + binary from the hub over HTTP (shared helpers in
 *      gw_fw_http.c).
 *   2. Stream blocks over the Spinel UART1 link to the NCP via vendor
 *      property 0x3C00 (NN_SPINEL_PROP_NCP_OTA_BLOCK).
 *   3. Send FINALIZE (0x3C01) with size + sha256 — NCP verifies, calls
 *      boot_request_upgrade, reboots into the new image.
 *   4. Poll NCP_VERSION until the new image comes up.
 *   5. Send CONFIRM (0x3C02) so MCUboot makes the new slot permanent.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/net/socket.h>

#include <nn_osal/osal.h>

#include "gw_fw_http.h"
#include "gw_peer_reset.h"
#include "gw_provision.h"
#include "ncp_link.h"
#include "ncp_ota_client.h"
#include "spinel.h"

NN_OSAL_LOG_MODULE(ncp_ota_client);

#define BLOCK_SIZE          NN_NCP_OTA_BLOCK_SIZE
#define BLOCK_TIMEOUT_MS    5000
#define FINALIZE_TIMEOUT_MS 15000
#define CONFIRM_TIMEOUT_MS  2000
#define BLOCK_RETRIES       3
#define BLOCK_BACKOFF_MS    200
/* Pause between blocks to let the net_buf pool drain — without this,
 * back-to-back HTTP recv → Spinel SET bursts exhaust NET_PKT_TX
 * even after bumping the pool, because the Spinel send path holds
 * the pkt across the UART1 TX while the HTTP path queues TCP ACKs. */
#define INTER_BLOCK_PAUSE_MS  10

/* Wait up to this long for the NCP to come back after FINALIZE.
 * MCUboot swap-scratch on a ~600KB NCP image was empirically observed
 * at >90s on the esp32-c6 — the OT-enabled NCP build has more flash
 * activity and SPI bus contention than the host self-OTA case.  180s
 * is the production-grade upper bound; if the chip doesn't come back
 * by then it's not coming back. */
#define POST_REBOOT_TIMEOUT_MS 180000
#define POST_REBOOT_POLL_MS    1000

K_MUTEX_DEFINE(s_ncp_ota_mutex);

static inline void put_u32_le(uint8_t *dst, uint32_t v)
{
	dst[0] = (uint8_t)(v & 0xff);
	dst[1] = (uint8_t)((v >> 8) & 0xff);
	dst[2] = (uint8_t)((v >> 16) & 0xff);
	dst[3] = (uint8_t)((v >> 24) & 0xff);
}

/* Send one block via Spinel SET.  Retries on:
 *   -EIO + last_status=BUSY  → NCP says it's busy, short backoff.
 *   -ETIMEDOUT               → no response within BLOCK_TIMEOUT_MS.
 *                              On the gateway this typically means the
 *                              host-side net_buf pool was momentarily
 *                              starved (BR traffic from NCP filling it
 *                              up).  Longer backoff to let it drain.
 */
static int send_block(uint32_t offset, const uint8_t *data, size_t data_len)
{
	uint8_t payload[4 + BLOCK_SIZE];
	if (data_len > BLOCK_SIZE) return -E2BIG;
	put_u32_le(payload, offset);
	memcpy(payload + 4, data, data_len);

	for (int attempt = 0; attempt < BLOCK_RETRIES; attempt++) {
		uint32_t last_status = 0;
		int rv = ncp_link_set_raw(NN_SPINEL_PROP_NCP_OTA_BLOCK,
					  payload, 4 + data_len,
					  &last_status,
					  K_MSEC(BLOCK_TIMEOUT_MS));
		if (rv == 0) return 0;
		if (rv == -EIO && last_status == /*SPINEL_STATUS_BUSY*/ 12) {
			NN_LOG_WRN("block @%u: NCP busy, retry %d/%d",
				offset, attempt + 1, BLOCK_RETRIES);
			nn_osal_sleep_ms(BLOCK_BACKOFF_MS);
			continue;
		}
		if (rv == -ETIMEDOUT) {
			NN_LOG_WRN("block @%u: -ETIMEDOUT (likely buf-pool "
				"starved), retry %d/%d",
				offset, attempt + 1, BLOCK_RETRIES);
			/* Longer backoff — let net_buf drain + sysworkq run. */
			nn_osal_sleep_ms(BLOCK_BACKOFF_MS * 4);
			continue;
		}
		NN_LOG_ERR("block @%u: rv=%d last_status=%u",
			offset, rv, last_status);
		return rv;
	}
	return -EIO;
}

static int send_finalize(uint32_t total_size, const uint8_t sha[32])
{
	uint8_t payload[4 + 32];
	put_u32_le(payload, total_size);
	memcpy(payload + 4, sha, 32);

	uint32_t last_status = 0;
	int rv = ncp_link_set_raw(NN_SPINEL_PROP_NCP_OTA_FINALIZE,
				  payload, sizeof(payload),
				  &last_status,
				  K_MSEC(FINALIZE_TIMEOUT_MS));
	/* The NCP reboots ~500ms after writing LAST_STATUS=OK, so the reply
	 * frame can race with the reboot.  -ETIMEDOUT *after* a successful
	 * send is "probably ok" — we'll detect via the post-reboot wait. */
	if (rv == 0) {
		NN_LOG_INF("finalize ack ok");
	} else if (rv == -ETIMEDOUT) {
		NN_LOG_INF("finalize: reply raced reboot (-ETIMEDOUT, expected)");
	} else {
		NN_LOG_ERR("finalize: rv=%d last_status=%u", rv, last_status);
		return rv;
	}
	return 0;
}

/* Wait for the NCP to come back online after FINALIZE-triggered reboot.
 * Uses the reset semaphore (signalled when the NCP's RX thread sees an
 * unsolicited LAST_STATUS=reset:power-on after the new image starts).
 * Once signalled, queries NCP_VERSION as a sanity check + to populate
 * out_ver.  Falls through to polling if the signal didn't fire (e.g.
 * the reset frame got dropped due to net_buf pressure). */
static int wait_for_ncp_back(char *out_ver, size_t cap)
{
	const int64_t deadline = nn_osal_uptime_ms() + POST_REBOOT_TIMEOUT_MS;

	NN_LOG_INF("waiting for NCP reset signal (up to %d ms)...",
		POST_REBOOT_TIMEOUT_MS);
	int rv = ncp_link_wait_reset(K_MSEC(POST_REBOOT_TIMEOUT_MS));
	if (rv == 0) {
		NN_LOG_INF("NCP reset signal received — querying NCP_VERSION");
	} else {
		NN_LOG_WRN("no reset signal within %d ms (rv=%d) — falling back to polling",
			POST_REBOOT_TIMEOUT_MS, rv);
	}

	/* Either the signal fired (fast path) or we timed out and try
	 * polling as fallback (handles the case where the unsolicited
	 * frame was dropped). */
	uint8_t buf[96];
	int  attempt = 0;
	while (nn_osal_uptime_ms() < deadline) {
		size_t buf_len = sizeof(buf);
		int gv = ncp_link_get(SPINEL_PROP_NCP_VERSION,
				      buf, &buf_len, K_MSEC(2000));
		if (gv == 0 && buf_len > 0) {
			size_t copy = NN_OSAL_MIN(cap - 1, buf_len);
			memcpy(out_ver, buf, copy);
			out_ver[copy] = 0;
			while (copy > 0 && out_ver[copy - 1] == '\0') copy--;
			out_ver[copy] = 0;
			return 0;
		}
		attempt++;
		NN_LOG_INF("NCP_VERSION poll #%d rv=%d (still booting?)",
			attempt, gv);
		nn_osal_sleep_ms(POST_REBOOT_POLL_MS);
	}
	NN_LOG_ERR("NCP did not respond to NCP_VERSION within %d ms",
		POST_REBOOT_TIMEOUT_MS);
	return -ETIMEDOUT;
}

static int send_confirm(bool make_permanent)
{
	uint8_t payload = make_permanent ? 1 : 0;
	uint32_t last_status = 0;
	int rv = ncp_link_set_raw(NN_SPINEL_PROP_NCP_OTA_CONFIRM,
				  &payload, 1, &last_status,
				  K_MSEC(CONFIRM_TIMEOUT_MS));
	if (rv != 0) {
		NN_LOG_ERR("confirm(%d): rv=%d last_status=%u",
			make_permanent, rv, last_status);
	}
	return rv;
}

/* ── public API ─────────────────────────────────────────────────── */

int ncp_ota_relay(const char *device_type, const char *version)
{
	if (!device_type || !version) return -EINVAL;
	if (k_mutex_lock(&s_ncp_ota_mutex, K_NO_WAIT) != 0) {
		NN_LOG_WRN("ncp_ota: another OTA already in progress");
		return -EBUSY;
	}
	int rv;
	const char *hub = gw_provision_get_hub_mdns();
	if (!hub) {
		NN_LOG_ERR("not provisioned");
		rv = -EAGAIN;
		goto out;
	}

	/* 1) Manifest. */
	struct gw_fw_manifest m;
	rv = gw_fw_fetch_manifest(hub, device_type, version, &m);
	if (rv < 0) {
		NN_LOG_ERR("manifest fetch: %d", rv);
		goto out;
	}
	NN_LOG_INF("ncp manifest %s/%s: size=%ld bytes, sha256=%02x%02x%02x%02x...",
		m.type, m.version, m.size,
		m.sha256[0], m.sha256[1], m.sha256[2], m.sha256[3]);

	/* 2) Open HTTP stream. */
	char uri[96];
	snprintf(uri, sizeof(uri), "/gw_firmware/%s/%s", device_type, version);
	long content_length = -1;
	int sock = gw_fw_http_open_get(hub, CONFIG_NN_PROTO_HUB_FW_PORT, uri,
				       &content_length, NULL, 0);
	if (sock < 0) { rv = sock; goto out; }
	if (content_length != m.size) {
		NN_LOG_ERR("Content-Length %ld != manifest size %ld",
			content_length, m.size);
		zsock_close(sock); rv = -EPROTO; goto out;
	}

	/* 3) Stream blocks; sha256 alongside. */
	psa_hash_operation_t op;
	rv = gw_fw_sha256_init(&op);
	if (rv) { zsock_close(sock); goto out; }

	uint8_t buf[BLOCK_SIZE];
	uint32_t offset = 0;
	int64_t t0 = nn_osal_uptime_ms();
	int last_pct = -1;
	while (offset < (uint32_t)content_length) {
		size_t want = NN_OSAL_MIN((size_t)content_length - offset, sizeof(buf));
		ssize_t got = zsock_recv(sock, buf, want, 0);
		if (got <= 0) {
			NN_LOG_ERR("recv at %u: rv=%zd errno=%d",
				offset, got, errno);
			rv = (got == 0) ? -EIO : -errno;
			zsock_close(sock); goto out;
		}
		(void)gw_fw_sha256_update(&op, buf, (size_t)got);
		rv = send_block(offset, buf, (size_t)got);
		if (rv) { zsock_close(sock); goto out; }
		offset += (uint32_t)got;
		nn_osal_sleep_ms(INTER_BLOCK_PAUSE_MS);
		int pct = (int)(((long)offset * 100) / content_length);
		if (pct >= last_pct + 10) {
			NN_LOG_INF("  ... %u / %ld B (%d%%)",
				offset, content_length, pct);
			last_pct = pct;
		}
	}
	zsock_close(sock);
	int64_t dur = nn_osal_uptime_ms() - t0;
	NN_LOG_INF("ncp upload ok: %u B in %lld ms (%u B/s)",
		offset, dur, dur > 0 ? (uint32_t)((long)offset * 1000 / dur) : 0);

	/* 4) Defense-in-depth: verify our local sha matches manifest before
	 * we ask the NCP to swap.  (NCP will also verify.) */
	uint8_t local_hash[32];
	rv = gw_fw_sha256_finish(&op, local_hash);
	if (rv) goto out;
	if (memcmp(local_hash, m.sha256, 32) != 0) {
		NN_LOG_ERR("local sha256 mismatch — refusing to FINALIZE");
		rv = -EBADMSG; goto out;
	}

	/* 5) FINALIZE.  Arm the reset semaphore BEFORE sending so we can't
	 * miss the unsolicited reset:power-on frame from the new image. */
	ncp_link_arm_reset_signal();
	rv = send_finalize(offset, m.sha256);
	if (rv) goto out;

	/* 6) Suppress outbound STREAM_NET while we hardware-reset the NCP
	 * and wait for it to come back.  Auto-clears when the reset signal
	 * arrives.  Without this, NCP's UART1 RX FIFO fills with garbage
	 * during MCUboot swap and the new image's HDLC framer can't
	 * resync. */
	ncp_link_set_quiet_for_ota(true);

	/* 7) Hardware-reset the NCP via GPIO 19 → NCP EN.  Software resets
	 * (sys_reboot, esp_restart) leave SPI1 in a state that hangs
	 * MCUboot mid-flash-init on the OT-NCP build.  Pulsing EN low is
	 * a true power-on-equivalent reset; MCUboot completes the swap
	 * cleanly and the new image boots. */
	nn_osal_sleep_ms(50);  /* let send_finalize's LAST_STATUS reply clock out */
	gw_peer_reset_pulse(100);

	/* 8) Wait for NCP to come back into the new image. */
	char ncp_ver[64] = {0};
	rv = wait_for_ncp_back(ncp_ver, sizeof(ncp_ver));
	/* Defensive: clear quiet in case wait_for_ncp_back fell through
	 * to the polling fallback (which doesn't auto-clear). */
	ncp_link_set_quiet_for_ota(false);
	if (rv) {
		NN_LOG_ERR("NCP did not come back within %d ms",
			POST_REBOOT_TIMEOUT_MS);
		goto out;
	}
	NN_LOG_INF("NCP back, NCP_VERSION='%s'", ncp_ver);

	/* 7) Confirm — make the new image permanent. */
	rv = send_confirm(true);
	if (rv) goto out;
	NN_LOG_INF("ncp ota: confirmed, %s/%s now permanent", device_type, version);
	rv = (int)offset;

out:
	k_mutex_unlock(&s_ncp_ota_mutex);
	return rv;
}

int ncp_ota_confirm(bool make_permanent)
{
	return send_confirm(make_permanent);
}

int ncp_ota_get_app_version(char *out, size_t cap)
{
	if (!out || cap == 0) return -EINVAL;
	uint8_t buf[64];
	size_t  buf_len = sizeof(buf);
	int rv = ncp_link_get(NN_SPINEL_PROP_NCP_OTA_APP_VERSION,
			      buf, &buf_len, K_MSEC(2000));
	if (rv == -EIO) {
		/* PROP_NOT_FOUND — NCP firmware doesn't have the vendor hook. */
		return -ENOTSUP;
	}
	if (rv) return rv;
	size_t copy = NN_OSAL_MIN(cap - 1, buf_len);
	memcpy(out, buf, copy);
	out[copy] = 0;
	/* Trim trailing NULs (Spinel UTF8 may include the terminator). */
	while (copy > 0 && out[copy - 1] == '\0') copy--;
	out[copy] = 0;
	return 0;
}

/* ── shell ───────────────────────────────────────────────────── */

static int cmd_ncp_ota(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 3) {
		nn_osal_shell_print(sh, "usage: gwota_ncp <device_type> <version>");
		return -EINVAL;
	}
	int rv = ncp_ota_relay(argv[1], argv[2]);
	nn_osal_shell_print(sh, "ncp_ota_relay rv=%d", rv);
	return rv < 0 ? rv : 0;
}

NN_OSAL_SHELL_CMD_REGISTER(gwota_ncp, cmd_ncp_ota, "gwota_ncp <device_type> <version> — relay an OTA to the NCP");

static int cmd_ncp_ota_confirm(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	bool perm = true;
	if (argc == 2 && strcmp(argv[1], "revert") == 0) perm = false;
	int rv = ncp_ota_confirm(perm);
	nn_osal_shell_print(sh, "ncp_ota_confirm(%d) rv=%d", perm, rv);
	return rv < 0 ? rv : 0;
}

NN_OSAL_SHELL_CMD_REGISTER(gwota_ncp_confirm, cmd_ncp_ota_confirm,
		   "gwota_ncp_confirm [revert] — send CONFIRM to NCP "
		   "(default: make permanent; 'revert' lets next reboot revert)");

/*
 * M2 bring-up helper — sends an empty SET on each of the three vendor
 * properties and reports what came back.  Useful when the host hasn't
 * been re-flashed with M3 changes yet.
 */
static int cmd_ncp_ota_ping(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc);
	NN_OSAL_UNUSED(argv);

	static const struct {
		uint32_t prop;
		const char *name;
	} props[] = {
		{ NN_SPINEL_PROP_NCP_OTA_BLOCK,    "BLOCK    (0x3C00)" },
		{ NN_SPINEL_PROP_NCP_OTA_FINALIZE, "FINALIZE (0x3C01)" },
		{ NN_SPINEL_PROP_NCP_OTA_CONFIRM,  "CONFIRM  (0x3C02)" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(props); i++) {
		uint32_t last_status = 0;
		int rv = ncp_link_set_raw(props[i].prop, NULL, 0,
					  &last_status, K_MSEC(2000));
		nn_osal_shell_print(sh, "  %s rv=%d last_status=%u",
			    props[i].name, rv, last_status);
	}
	return 0;
}

NN_OSAL_SHELL_CMD_REGISTER(gwota_ncp_ping, cmd_ncp_ota_ping,
		   "gwota_ncp_ping — send empty SET on each NCP OTA vendor "
		   "property; expects LAST_STATUS=OK if NCP has vendor hook");

static int cmd_ncp_app_version(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	char ver[64] = {0};
	int rv = ncp_ota_get_app_version(ver, sizeof(ver));
	if (rv == 0) {
		nn_osal_shell_print(sh, "NCP app version: %s", ver);
	} else if (rv == -ENOTSUP) {
		nn_osal_shell_print(sh, "NCP firmware lacks the vendor hook (PROP_NOT_FOUND).");
	} else {
		nn_osal_shell_print(sh, "ncp_ota_get_app_version rv=%d", rv);
	}
	return rv < 0 ? rv : 0;
}

NN_OSAL_SHELL_CMD_REGISTER(gwota_ncp_version, cmd_ncp_app_version, "gwota_ncp_version — read NCP_APP_VERSION (Spinel 0x3C03)");
