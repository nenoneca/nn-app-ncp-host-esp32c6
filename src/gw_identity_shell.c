/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Zephyr shell commands for gw_identity.  Split from the core
 * implementation (now in modules/libs/fw_common/src/gw_identity.c)
 * because the shell + the gw_send_hello plumbing pull in
 * apps-specific dependencies (proto_tcp, nn_proto_encode) that we
 * don't want creeping into the platform-neutral lib.
 *
 * If/when the Linux gateway daemon (host/gw_linux/) wants the same
 * "show identity" CLI, it'll either implement equivalent getopt
 * subcommands directly or factor those out too — but for now this
 * file stays Zephyr-only.
 */

#include <errno.h>
#include <stdbool.h>


#include <nn_osal/osal.h>
#include <fw_common/gw_identity.h>
#include <nn_proto/nn_proto.h>

#include "proto_tcp.h"

NN_OSAL_LOG_MODULE(gw_identity_shell);

static int cmd_gw_id(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);

	const uint8_t *id  = gw_identity_get_id();
	const uint8_t *pub = gw_identity_get_pubkey();
	if (!id || !pub) {
		nn_osal_shell_error(sh, "gw_identity not initialised");
		return -ENODEV;
	}
	nn_osal_shell_print(sh, "gateway_id : %02x%02x%02x%02x%02x%02x%02x%02x",
		    id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]);
	char pub_hex[GW_IDENTITY_PUBKEY_LEN * 2 + 1];
	for (int i = 0; i < GW_IDENTITY_PUBKEY_LEN; i++) {
		snprintf(pub_hex + i * 2, 3, "%02x", pub[i]);
	}
	nn_osal_shell_print(sh, "p256_pub   : %s", pub_hex);
	return 0;
}

static int cmd_gw_init(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int rv = gw_identity_init();
	nn_osal_shell_print(sh, "gw_identity_init() returned %d", rv);
	return rv;
}

static int cmd_gw_signtest(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	const uint8_t *pub = gw_identity_get_pubkey();
	if (!pub) {
		nn_osal_shell_error(sh, "gw_identity not initialised");
		return -ENODEV;
	}
	const uint8_t msg[] = "nn_proto signtest";
	uint8_t sig[64];
	int rv = gw_identity_sign(NULL, msg, sizeof(msg) - 1, sig);
	if (rv) {
		nn_osal_shell_error(sh, "sign rv=%d", rv);
		return rv;
	}
	nn_osal_shell_print(sh, "sign ok (64B)");
	rv = gw_identity_verify((void *)pub, msg, sizeof(msg) - 1, sig);
	nn_osal_shell_print(sh, "verify rv=%d", rv);
	return rv;
}

static int cmd_gw_hub(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: gw hub <hostname>");
		return -EINVAL;
	}
	int rv = proto_tcp_set_hub_hostname(argv[1]);
	nn_osal_shell_print(sh, "set hub hostname → %s (rv=%d)", argv[1], rv);
	return rv;
}

static const char *state_name(enum proto_tcp_state s)
{
	switch (s) {
	case PROTO_TCP_DOWN:       return "down";
	case PROTO_TCP_CONNECTING: return "connecting";
	case PROTO_TCP_UP:         return "up";
	default:                   return "?";
	}
}

static int cmd_gw_status(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	struct proto_tcp_stats st;
	proto_tcp_get_stats(&st);
	nn_osal_shell_print(sh, "tcp state    : %s", state_name(proto_tcp_get_state()));
	nn_osal_shell_print(sh, "connects     : %u  failures: %u  disconnects: %u",
		    st.connects, st.connect_failures, st.disconnects);
	nn_osal_shell_print(sh, "tx           : frames=%u bytes=%u  drops_full=%u drops_sock=%u",
		    st.tx_frames, st.tx_bytes,
		    st.tx_drops_full, st.tx_drops_socket);
	nn_osal_shell_print(sh, "rx           : frames=%u bytes=%u  drops_oversize=%u drops_bad=%u",
		    st.rx_frames, st.rx_bytes,
		    st.rx_drops_oversize, st.rx_drops_bad);
	return 0;
}

/* Build + sign + enqueue a single D2G HUB_STATUS_QUERY. */
static int cmd_gw_send_hello(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	const uint8_t *gw_id = gw_identity_get_id();
	if (!gw_id) {
		nn_osal_shell_error(sh, "gw_identity not initialised");
		return -ENODEV;
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
		nn_osal_shell_error(sh, "encode rv=%d", n);
		return n;
	}
	int rv = proto_tcp_enqueue(frame, (size_t)n);
	nn_osal_shell_print(sh, "encoded %d B; enqueue rv=%d", n, rv);
	return rv;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(gw_subs,
	NN_OSAL_SHELL_CMD(id, cmd_gw_id, "Print gateway_id and P-256 public key"),
	NN_OSAL_SHELL_CMD(init, cmd_gw_init, "Re-run gw_identity_init() and print rc"),
	NN_OSAL_SHELL_CMD(signtest, cmd_gw_signtest, "Sign+verify a known message"),
	NN_OSAL_SHELL_CMD(hub, cmd_gw_hub, "gw hub <hostname>: set hub mDNS name"),
	NN_OSAL_SHELL_CMD(status, cmd_gw_status, "Print TCP transport state + counters"),
	NN_OSAL_SHELL_CMD(send_hello, cmd_gw_send_hello, "Sign+enqueue one D2G HUB_STATUS_QUERY"),
	NN_OSAL_SHELL_SUBCMD_SET_END
);
NN_OSAL_SHELL_CMD_REGISTER_SET(gw, &gw_subs, NULL, "Gateway identity / broker controls");
