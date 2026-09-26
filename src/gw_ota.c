/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <psa/crypto.h>
#include <nn_pal/dfu.h>
#include <zephyr/net/socket.h>
#include <zephyr/dfu/mcuboot.h>   /* boot_is_img_confirmed */
/* nn_osal_sys_reboot via nn_osal/system.h (included by osal.h) */

#include <nn_osal/osal.h>

#include "gw_fw_http.h"
#include "gw_ota.h"
#include "gw_provision.h"
#include "ncp_ota_client.h"
#include "proto_tcp.h"

NN_OSAL_LOG_MODULE(gw_ota);

#define HUB_FW_PORT  CONFIG_NN_PROTO_HUB_FW_PORT
#define RECV_CHUNK   1024

/* Health gate before we mark the running image permanent. */
#define MIN_UPTIME_BEFORE_CONFIRM_MS  30000
#define CONFIRM_POLL_PERIOD_MS         2000

/* ── re-entry guard ─────────────────────────────────────────────── */

K_MUTEX_DEFINE(s_ota_mutex);

/* ── bundle reconciliation (M5) ────────────────────────────────── */

#define BUNDLED_NCP_VERSION CONFIG_NN_BUNDLED_NCP_VERSION
#define BUNDLED_NCP_TYPE    CONFIG_NN_BUNDLED_NCP_TYPE
#define BUNDLE_RECONCILE_MAX_ATTEMPTS  CONFIG_NN_BUNDLE_RECONCILE_MAX_ATTEMPTS

static int s_bundle_attempts;

/* Returns 0 if bundle is OK to confirm (NCP at expected version OR
 * pairing disabled); -EAGAIN if mismatched and we should retry; -EFAULT
 * if we've exhausted attempts and should give up (don't confirm). */
static int reconcile_ncp_bundle(void)
{
	/* Pairing disabled — no version constraint. */
	if (strcmp(BUNDLED_NCP_VERSION, "0.0.0") == 0) {
		return 0;
	}

	char ncp_ver[64] = {0};
	int rv = ncp_ota_get_app_version(ncp_ver, sizeof(ncp_ver));
	if (rv == -ETIMEDOUT) {
		NN_LOG_DBG("bundle: NCP version query timed out (link not ready?)");
		return -EAGAIN;
	}
	if (rv == -ENOTSUP) {
		/* NCP firmware predates the vendor hook.  We can't verify
		 * pairing — best we can do is push the bundled image and
		 * trust that the post-OTA NCP will then expose the prop. */
		NN_LOG_WRN("bundle: NCP lacks vendor hook — pushing %s/%s blind",
			BUNDLED_NCP_TYPE, BUNDLED_NCP_VERSION);
	} else if (rv == 0 && strcmp(ncp_ver, BUNDLED_NCP_VERSION) == 0) {
		if (s_bundle_attempts > 0) {
			NN_LOG_INF("bundle: NCP now at %s — reconciled", ncp_ver);
		}
		return 0;
	} else if (rv == 0) {
		NN_LOG_INF("bundle: NCP at %s, expected %s — pushing",
			ncp_ver, BUNDLED_NCP_VERSION);
	} else {
		NN_LOG_WRN("bundle: NCP version query rv=%d", rv);
		return -EAGAIN;
	}

	if (s_bundle_attempts >= BUNDLE_RECONCILE_MAX_ATTEMPTS) {
		NN_LOG_ERR("bundle: %d push attempts failed — giving up; "
			"host will reboot to old slot",
			s_bundle_attempts);
		return -EFAULT;
	}
	s_bundle_attempts++;
	rv = ncp_ota_relay(BUNDLED_NCP_TYPE, BUNDLED_NCP_VERSION);
	if (rv >= 0) {
		NN_LOG_INF("bundle: ncp push attempt %d ok (%d B)",
			s_bundle_attempts, rv);
		/* Don't return 0 directly — let the next iteration query
		 * NCP_APP_VERSION fresh and confirm the version actually
		 * matches before we promote the host. */
		return -EAGAIN;
	}
	NN_LOG_WRN("bundle: ncp push attempt %d failed: %d",
		s_bundle_attempts, rv);
	return -EAGAIN;
}

/* ── delayed-confirm worker ─────────────────────────────────────── */

static void confirm_when_healthy(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_confirm_work, confirm_when_healthy);

static void confirm_when_healthy(struct k_work *w)
{
	NN_OSAL_UNUSED(w);
	int already = boot_is_img_confirmed();
	if (already > 0) {
		return;  /* already permanent */
	}
	int64_t up = nn_osal_uptime_ms();
	bool tcp_up = (proto_tcp_get_state() == PROTO_TCP_UP);
	if (up < MIN_UPTIME_BEFORE_CONFIRM_MS || !tcp_up) {
		k_work_reschedule(&s_confirm_work,
				  K_MSEC(CONFIRM_POLL_PERIOD_MS));
		return;
	}

	/* Bundle gate: NCP must be at CONFIG_NN_BUNDLED_NCP_VERSION (or
	 * pairing disabled) before we promote ourselves to permanent. */
	int br = reconcile_ncp_bundle();
	if (br == -EAGAIN) {
		k_work_reschedule(&s_confirm_work,
				  K_MSEC(CONFIRM_POLL_PERIOD_MS));
		return;
	}
	if (br == -EFAULT) {
		/* Don't reschedule — give up and let the next reboot
		 * (manual or watchdog) revert the host to slot0. */
		NN_LOG_ERR("not confirming — bundle reconciliation gave up");
		return;
	}

	int rv = nn_pal_dfu_confirm();
	if (rv == 0) {
		NN_LOG_INF("running image confirmed (uptime=%lld ms, tcp=up%s)",
			up,
			strcmp(BUNDLED_NCP_VERSION, "0.0.0") == 0
				? "" : ", ncp=match");
	} else {
		NN_LOG_WRN("dfu_confirm: %d (will retry)", rv);
		k_work_reschedule(&s_confirm_work, K_SECONDS(10));
	}
}

/* ── public API ─────────────────────────────────────────────────── */

int gw_ota_init(void)
{
	nn_pal_dfu_state_t st = NN_PAL_DFU_STATE_UNKNOWN;
	(void)nn_pal_dfu_get_state(&st);
	if (st == NN_PAL_DFU_STATE_RUNNING_CONFIRMED) {
		NN_LOG_INF("running image already confirmed (slot0 known-good)");
		return 0;
	}
	if (st == NN_PAL_DFU_STATE_RUNNING_PENDING) {
		NN_LOG_INF("running image is in TEST mode — confirm-on-health "
			"worker armed (uptime≥%d ms + TCP up)",
			MIN_UPTIME_BEFORE_CONFIRM_MS);
	} else {
		NN_LOG_WRN("dfu_get_state: %d", (int)st);
	}
	/* First poll a moment after boot — gives the rest of the system
	 * a chance to come up before we even glance at it. */
	k_work_reschedule(&s_confirm_work, K_SECONDS(5));
	return 0;
}

int gw_ota_confirm(void)
{
	int rv = nn_pal_dfu_confirm();
	if (rv == 0) {
		NN_LOG_INF("manually confirmed running image");
	}
	return rv;
}

/* ── core download ──────────────────────────────────────────────── */

int gw_ota_download(const char *device_type, const char *version,
		    bool request_upgrade_after)
{
	if (!device_type || !version) return -EINVAL;
	if (k_mutex_lock(&s_ota_mutex, K_NO_WAIT) != 0) {
		NN_LOG_WRN("gw_ota: another OTA already in progress");
		return -EBUSY;
	}
	int rv;
	const char *hub_mdns = gw_provision_get_hub_mdns();
	if (!hub_mdns) {
		rv = -EAGAIN;
		NN_LOG_ERR("not provisioned — run `provision set ...`");
		goto out;
	}

	/* 1) Manifest first — sanity-check size + hash before we erase. */
	struct gw_fw_manifest m;
	rv = gw_fw_fetch_manifest(hub_mdns, device_type, version, &m);
	if (rv < 0) {
		NN_LOG_ERR("manifest fetch: %d", rv);
		goto out;
	}
	NN_LOG_INF("manifest %s/%s: size=%ld bytes, sha256=%02x%02x%02x%02x...",
		m.type, m.version, m.size,
		m.sha256[0], m.sha256[1], m.sha256[2], m.sha256[3]);

	/* 2) Open the binary stream. */
	char uri[96];
	snprintf(uri, sizeof(uri), "/gw_firmware/%s/%s", device_type, version);
	long content_length = -1;
	char hdr_sha[80] = {0};
	int sock = gw_fw_http_open_get(hub_mdns, HUB_FW_PORT, uri,
				       &content_length, hdr_sha, sizeof(hdr_sha));
	if (sock < 0) { rv = sock; goto out; }

	if (content_length != m.size) {
		NN_LOG_ERR("Content-Length %ld != manifest size %ld",
			content_length, m.size);
		zsock_close(sock);
		rv = -EPROTO;
		goto out;
	}

	/* 3) Stream into slot1 + hash. */
	nn_pal_dfu_ctx_t *dctx = nn_pal_dfu_ctx_alloc();
	if (!dctx) { NN_LOG_ERR("dfu_ctx_alloc"); zsock_close(sock); rv = -ENOMEM; goto out; }
	rv = nn_pal_dfu_begin(dctx, (size_t)content_length);
	if (rv) { NN_LOG_ERR("dfu_begin: %d", rv); nn_pal_dfu_ctx_free(dctx); zsock_close(sock); goto out; }
	psa_hash_operation_t op;
	rv = gw_fw_sha256_init(&op);
	if (rv) { nn_pal_dfu_ctx_free(dctx); zsock_close(sock); goto out; }

	uint8_t buf[RECV_CHUNK];
	long total = 0;
	int64_t t0 = nn_osal_uptime_ms();
	int last_pct = -1;
	while (total < content_length) {
		size_t want = NN_OSAL_MIN((size_t)(content_length - total), sizeof(buf));
		ssize_t got = zsock_recv(sock, buf, want, 0);
		if (got <= 0) {
			NN_LOG_ERR("recv at %ld: rv=%zd errno=%d",
				total, got, errno);
			rv = (got == 0) ? -EIO : -errno;
			nn_pal_dfu_ctx_free(dctx);
			zsock_close(sock); goto out;
		}
		int wrv = nn_pal_dfu_write(dctx, buf, (size_t)got);
		if (wrv) {
			NN_LOG_ERR("flash write at %ld: %d", total, wrv);
			rv = wrv;
			nn_pal_dfu_ctx_free(dctx);
			zsock_close(sock); goto out;
		}
		(void)gw_fw_sha256_update(&op, buf, (size_t)got);
		total += got;
		if ((total >= content_length)) {
			int frc = nn_pal_dfu_finalise(dctx);
			if (frc) {
				NN_LOG_ERR("dfu_finalise: %d", frc);
				rv = frc;
				nn_pal_dfu_ctx_free(dctx);
				zsock_close(sock); goto out;
			}
		}
		int pct = (int)((total * 100) / content_length);
		if (pct >= last_pct + 10) {
			NN_LOG_INF("  ... %ld / %ld B (%d%%)",
				total, content_length, pct);
			last_pct = pct;
		}
	}
	nn_pal_dfu_ctx_free(dctx);
	zsock_close(sock);

	/* 4) Verify SHA-256 against manifest. */
	uint8_t got_hash[32];
	rv = gw_fw_sha256_finish(&op, got_hash);
	if (rv) goto out;
	if (memcmp(got_hash, m.sha256, 32) != 0) {
		NN_LOG_ERR("sha256 MISMATCH — manifest=%02x%02x... got=%02x%02x...",
			m.sha256[0], m.sha256[1],
			got_hash[0], got_hash[1]);
		rv = -EBADMSG;
		goto out;
	}
	int64_t dur = nn_osal_uptime_ms() - t0;
	NN_LOG_INF("download+verify ok: %ld B in %lld ms (%ld B/s, sha256✓)",
		total, dur, dur > 0 ? (total * 1000) / dur : 0);

	if (request_upgrade_after) {
		rv = nn_pal_dfu_request_upgrade(false);
		if (rv) { NN_LOG_ERR("dfu_request_upgrade: %d", rv); goto out; }
		NN_LOG_INF("upgrade staged — rebooting in 1s");
		k_mutex_unlock(&s_ota_mutex);
		nn_osal_sleep_ms(1000);
		nn_osal_sys_reboot(NN_OSAL_REBOOT_COLD);
		__builtin_unreachable();
	}
	rv = (int)total;

out:
	k_mutex_unlock(&s_ota_mutex);
	return rv;
}

/* ── shell ───────────────────────────────────────────────────── */

static int cmd_ota_download(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 3) {
		nn_osal_shell_print(sh, "usage: gwota download <device_type> <version>");
		return -EINVAL;
	}
	int rv = gw_ota_download(argv[1], argv[2], false);
	nn_osal_shell_print(sh, "download rv=%d", rv);
	return rv < 0 ? rv : 0;
}

static int cmd_ota_apply(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 3) {
		nn_osal_shell_print(sh, "usage: gwota apply <device_type> <version>");
		return -EINVAL;
	}
	int rv = gw_ota_download(argv[1], argv[2], true);
	nn_osal_shell_print(sh, "download+apply rv=%d", rv);
	return rv < 0 ? rv : 0;
}

static int cmd_ota_confirm(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int rv = gw_ota_confirm();
	nn_osal_shell_print(sh, "confirm rv=%d", rv);
	return 0;
}

static int cmd_ota_status(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int confirmed = boot_is_img_confirmed();
	nn_osal_shell_print(sh, "running image confirmed: %s",
		    confirmed > 0 ? "yes" : "no (test mode)");
	nn_osal_shell_print(sh, "uptime ms : %lld", nn_osal_uptime_ms());
	nn_osal_shell_print(sh, "tcp state : %d (%s)",
		    proto_tcp_get_state(),
		    proto_tcp_get_state() == PROTO_TCP_UP ? "up" : "down/connecting");
	return 0;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(ota_subs,
	NN_OSAL_SHELL_CMD(download, cmd_ota_download, "download <type> <ver>"),
	NN_OSAL_SHELL_CMD(apply, cmd_ota_apply, "apply <type> <ver> — download+stage+reboot (test mode)"),
	NN_OSAL_SHELL_CMD(confirm, cmd_ota_confirm, "manually confirm running image"),
	NN_OSAL_SHELL_CMD(status, cmd_ota_status, "show MCUboot/health state"),
	NN_OSAL_SHELL_SUBCMD_SET_END
);
NN_OSAL_SHELL_CMD_REGISTER_SET(gwota, &ota_subs, NULL, "Gateway-side OTA controls");
