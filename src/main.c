/* SPDX-License-Identifier: Apache-2.0 */

/*
 * ESP32-C6 NCP Host — Milestones A/B bring-up shell.
 */

#include "border_agent.h"
#include "gw_ble_provision.h"
#include "gw_commands.h"
#include "gw_identity.h"
#include "gw_ot_apply.h"
#include "gw_ota.h"
#include "gw_peer_reset.h"
#include "gw_provision.h"
#include "gw_watchdog.h"
#include "proto_router.h"
#include "proto_tcp.h"
#include "proto_udp.h"
#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>
#include "ncp_link.h"
#include "ncp_netif.h"
#include "ra_sender.h"
#include "spinel.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/drivers/led_strip.h>
#include <nn_pal/mdns.h>
#include <zephyr/net/net_ip.h>

/*
 * Advertise _meshcop._udp on WiFi so Thread commissioners (phone apps,
 * ot-commissioner) can discover this Border Router.  Port 49191 is the
 * Border Agent UDP listener, which we forward to the NCP.
 *
 * TXT record is minimal — a full meshcop TXT would include rv, tv, sb,
 * nn, xp, sv, etc., but discovery alone works with an empty record.
 */
/* TXT key=val list for the meshcop Border Agent advertisement. */
static const nn_pal_mdns_txt_t nn_meshcop_txt[] = {
	{ "sv", "thread" },
};

NN_OSAL_LOG_MODULE(ncp_host);

/*
 * Weak stubs for WiFi wpa_supplicant symbols that Zephyr declares but
 * the ESP32-C6 net80211 blob does not provide.  Same pattern used in
 * apps/tbr_esp32c6/src/main.c — returning 0 is safe (no NVS PMK reset
 * pending).  Needed for WPA2-PSK connects.
 */
__attribute__((weak)) uint8_t esp_wifi_sta_get_reset_nvs_pmk_internal(void)
{
	return 0;
}

__attribute__((weak)) uint8_t esp_wifi_sta_set_reset_nvs_pmk_internal(uint8_t v)
{
	(void)v;
	return 0;
}

__attribute__((weak)) int esp_wifi_ap_get_transition_disable_internal(void)
{
	return 0;
}

/* Zephyr OT platform glue calls assert() without an include. */
#include <zephyr/sys/__assert.h>
__attribute__((weak)) void assert(int expr)
{
	if (!expr) {
		__ASSERT(0, "OT platform assert");
	}
}

#define GET_TIMEOUT K_MSEC(1000)
#define SET_TIMEOUT K_MSEC(2000)

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	return -1;
}

/* Decode a hex string ("AABBCC...") into buf.  Returns byte count or -1. */
static int hex_decode(const char *s, uint8_t *buf, size_t cap)
{
	size_t n = 0;
	while (*s) {
		int hi = hex_nibble(*s++);
		if (hi < 0 || !*s) return -1;
		int lo = hex_nibble(*s++);
		if (lo < 0) return -1;
		if (n >= cap) return -1;
		buf[n++] = (uint8_t)((hi << 4) | lo);
	}
	return (int)n;
}

static const char *role_name(uint8_t r)
{
	switch (r) {
	case SPINEL_NET_ROLE_DETACHED: return "detached";
	case SPINEL_NET_ROLE_CHILD:    return "child";
	case SPINEL_NET_ROLE_ROUTER:   return "router";
	case SPINEL_NET_ROLE_LEADER:   return "leader";
	case SPINEL_NET_ROLE_DISABLED: return "disabled";
	}
	return "unknown";
}

static void hex_dump(nn_osal_shell_ctx_t *sh, const uint8_t *buf, size_t len)
{
	char line[3 * 16 + 1];
	for (size_t i = 0; i < len; i += 16) {
		size_t n = MIN((size_t)16, len - i);
		char *p = line;
		for (size_t j = 0; j < n; j++) {
			p += snprintf(p, sizeof(line) - (p - line),
				      "%02x ", buf[i + j]);
		}
		nn_osal_shell_print(sh, "  %04zx: %s", i, line);
	}
}

static int cmd_ncp_version(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t  buf[256];
	size_t   len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_NCP_VERSION, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get NCP_VERSION: %d", rv);
		return rv;
	}
	/* NCP_VERSION is a null-terminated UTF-8 string. */
	size_t slen = strnlen((const char *)buf, len);
	nn_osal_shell_print(sh, "NCP_VERSION (%zu): %.*s",
		    slen, (int)slen, (const char *)buf);
	return 0;
}

static int cmd_ncp_proto(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t  buf[32];
	size_t   len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_PROTOCOL_VERSION, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get PROTOCOL_VERSION: %d", rv);
		return rv;
	}
	uint32_t major = 0, minor = 0;
	int r1 = spinel_unpack_uint(buf, len, &major);
	if (r1 > 0) {
		(void)spinel_unpack_uint(buf + r1, len - r1, &minor);
	}
	nn_osal_shell_print(sh, "PROTOCOL_VERSION: %u.%u", major, minor);
	return 0;
}

static int cmd_ncp_caps(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t  buf[512];
	size_t   len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_CAPS, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get CAPS: %d", rv);
		return rv;
	}
	nn_osal_shell_print(sh, "CAPS (%zu bytes):", len);
	size_t off = 0;
	int n = 0;
	while (off < len) {
		uint32_t id = 0;
		int r = spinel_unpack_uint(buf + off, len - off, &id);
		if (r < 0) break;
		nn_osal_shell_print(sh, "  [%d] %u", n, id);
		off += (size_t)r;
		n++;
	}
	return 0;
}

static int cmd_ncp_hwaddr(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t  buf[16];
	size_t   len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_HWADDR, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get HWADDR: %d", rv);
		return rv;
	}
	if (len != 8) {
		nn_osal_shell_warn(sh, "HWADDR unexpected len %zu", len);
	}
	nn_osal_shell_print(sh, "HWADDR: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		    buf[0], buf[1], buf[2], buf[3],
		    buf[4], buf[5], buf[6], buf[7]);
	return 0;
}

static int cmd_ncp_raw_set(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 3) {
		nn_osal_shell_error(sh, "usage: ncp raw-set <prop-id> <hex-bytes>");
		return -EINVAL;
	}
	uint32_t prop = (uint32_t)strtoul(argv[1], NULL, 0);
	uint8_t  payload[32];
	int n = hex_decode(argv[2], payload, sizeof(payload));
	if (n < 0) {
		nn_osal_shell_error(sh, "bad hex");
		return -EINVAL;
	}
	uint32_t ls = 0;
	int rv = ncp_link_set_raw(prop, payload, (size_t)n, &ls, SET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "SET %u: rv=%d last-status=%u (%s)",
			    prop, rv, ls, spinel_status_str(ls));
		return rv;
	}
	nn_osal_shell_print(sh, "SET %u: ok", prop);
	return 0;
}

static int cmd_ncp_raw_get(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp raw-get <prop-id>");
		return -EINVAL;
	}
	uint32_t prop = (uint32_t)strtoul(argv[1], NULL, 0);
	uint8_t  buf[512];
	size_t   len = sizeof(buf);
	int rv = ncp_link_get(prop, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get %u: %d", prop, rv);
		return rv;
	}
	nn_osal_shell_print(sh, "prop %u -> %zu bytes:", prop, len);
	hex_dump(sh, buf, len);
	return 0;
}

static int cmd_ncp_stats(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	struct ncp_link_stats s;
	ncp_link_stats_get(&s);
	nn_osal_shell_print(sh, "link rx_frames=%u rx_bytes=%u",
		    s.rx_frames, s.rx_bytes);
	nn_osal_shell_print(sh, "link tx_frames=%u tx_bytes=%u",
		    s.tx_frames, s.tx_bytes);
	nn_osal_shell_print(sh, "link rx_bad_fcs=%u rx_unsolicited=%u",
		    s.rx_bad_fcs, s.rx_unsolicited);

	struct ncp_netif_stats n;
	ncp_netif_stats_get(&n);
	nn_osal_shell_print(sh, "netif rx pkts=%u bytes=%u drops=%u",
		    n.rx_packets, n.rx_bytes, n.rx_drops);
	nn_osal_shell_print(sh, "netif tx pkts=%u bytes=%u drops=%u",
		    n.tx_packets, n.tx_bytes, n.tx_drops);

	struct border_agent_stats ba;
	border_agent_stats_get(&ba);
	nn_osal_shell_print(sh, "ba comm->ncp=%u (%u fwd) ncp->comm=%u (%u sent) drops=%u",
		    ba.rx_from_commissioner, ba.tx_to_ncp,
		    ba.rx_from_ncp, ba.tx_to_commissioner, ba.drops);
	return 0;
}

/* ---------- Milestone B1: Thread bring-up ---------- */

static int set_and_report(nn_osal_shell_ctx_t *sh, const char *label,
			  uint32_t prop, const uint8_t *payload, size_t len)
{
	uint32_t ls = 0;
	int rv = ncp_link_set_raw(prop, payload, len, &ls, SET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "%s: rv=%d last-status=%u (%s)",
			    label, rv, ls, spinel_status_str(ls));
		return rv;
	}
	nn_osal_shell_print(sh, "%s: ok", label);
	return 0;
}

static int cmd_ncp_ifconfig(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2 || (strcmp(argv[1], "up") && strcmp(argv[1], "down"))) {
		nn_osal_shell_error(sh, "usage: ncp ifconfig up|down");
		return -EINVAL;
	}
	bool up = strcmp(argv[1], "up") == 0;
	return set_and_report(sh, up ? "ifconfig up" : "ifconfig down",
			      SPINEL_PROP_NET_IF_UP, (uint8_t[]){ up }, 1);
}

static int cmd_ncp_thread(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2 || (strcmp(argv[1], "start") && strcmp(argv[1], "stop"))) {
		nn_osal_shell_error(sh, "usage: ncp thread start|stop");
		return -EINVAL;
	}
	bool up = strcmp(argv[1], "start") == 0;
	return set_and_report(sh, up ? "thread start" : "thread stop",
			      SPINEL_PROP_NET_STACK_UP, (uint8_t[]){ up }, 1);
}

static int cmd_ncp_role(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t buf[4];
	size_t len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_NET_ROLE, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get NET_ROLE: %d", rv);
		return rv;
	}
	if (len < 1) {
		nn_osal_shell_error(sh, "NET_ROLE empty reply");
		return -EIO;
	}
	nn_osal_shell_print(sh, "role: %u (%s)", buf[0], role_name(buf[0]));
	return 0;
}

static int cmd_ncp_state(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t b[4]; size_t l;

	l = sizeof(b);
	if (ncp_link_get(SPINEL_PROP_NET_IF_UP, b, &l, GET_TIMEOUT) == 0 && l >= 1) {
		nn_osal_shell_print(sh, "if-up:    %u", b[0]);
	}
	l = sizeof(b);
	if (ncp_link_get(SPINEL_PROP_NET_STACK_UP, b, &l, GET_TIMEOUT) == 0 && l >= 1) {
		nn_osal_shell_print(sh, "stack-up: %u", b[0]);
	}
	l = sizeof(b);
	if (ncp_link_get(SPINEL_PROP_NET_ROLE, b, &l, GET_TIMEOUT) == 0 && l >= 1) {
		nn_osal_shell_print(sh, "role:     %u (%s)", b[0], role_name(b[0]));
	}
	return 0;
}

static int cmd_ncp_channel(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp channel <11-26>");
		return -EINVAL;
	}
	uint32_t ch = (uint32_t)strtoul(argv[1], NULL, 0);
	if (ch < 11 || ch > 26) {
		nn_osal_shell_error(sh, "channel must be 11..26");
		return -EINVAL;
	}
	uint8_t v = (uint8_t)ch;
	return set_and_report(sh, "channel", SPINEL_PROP_PHY_CHAN, &v, 1);
}

static int cmd_ncp_panid(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp panid <0xNNNN>");
		return -EINVAL;
	}
	uint32_t p = (uint32_t)strtoul(argv[1], NULL, 0);
	if (p > 0xffff) {
		nn_osal_shell_error(sh, "panid out of range");
		return -EINVAL;
	}
	uint8_t v[2] = { (uint8_t)(p & 0xff), (uint8_t)(p >> 8) };
	return set_and_report(sh, "panid", SPINEL_PROP_MAC_15_4_PANID, v, 2);
}

static int cmd_ncp_netname(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp netname <name>");
		return -EINVAL;
	}
	size_t n = strlen(argv[1]);
	uint8_t buf[32];
	if (n + 1 > sizeof(buf)) {
		nn_osal_shell_error(sh, "name too long");
		return -EINVAL;
	}
	memcpy(buf, argv[1], n);
	buf[n] = '\0';
	return set_and_report(sh, "netname",
			      SPINEL_PROP_NET_NETWORK_NAME, buf, n + 1);
}

static int cmd_ncp_xpanid(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp xpanid <hex16>   (8 bytes, 16 hex chars)");
		return -EINVAL;
	}
	uint8_t buf[8];
	int n = hex_decode(argv[1], buf, sizeof(buf));
	if (n != 8) {
		nn_osal_shell_error(sh, "xpanid must be exactly 16 hex chars");
		return -EINVAL;
	}
	return set_and_report(sh, "xpanid", SPINEL_PROP_NET_XPANID, buf, 8);
}

static int cmd_ncp_netkey(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		nn_osal_shell_error(sh, "usage: ncp netkey <hex32>   (16 bytes, 32 hex chars)");
		return -EINVAL;
	}
	uint8_t buf[16];
	int n = hex_decode(argv[1], buf, sizeof(buf));
	if (n != 16) {
		nn_osal_shell_error(sh, "netkey must be exactly 32 hex chars");
		return -EINVAL;
	}
	return set_and_report(sh, "netkey", SPINEL_PROP_NET_NETWORK_KEY, buf, 16);
}

static void print_ipv6(nn_osal_shell_ctx_t *sh, const char *label,
		       const uint8_t *addr)
{
	char str[NET_IPV6_ADDR_LEN];
	if (net_addr_ntop(NET_AF_INET6, addr, str, sizeof(str)) != NULL) {
		nn_osal_shell_print(sh, "%s: %s", label, str);
	} else {
		nn_osal_shell_print(sh, "%s: <bad addr>", label);
	}
}

static int cmd_ncp_mladdr(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t buf[16];
	size_t len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_IPV6_ML_ADDR, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get ML_ADDR: %d", rv);
		return rv;
	}
	if (len < 16) {
		nn_osal_shell_error(sh, "short ML_ADDR (%zu)", len);
		return -EIO;
	}
	print_ipv6(sh, "ML", buf);
	return 0;
}

static int cmd_ncp_lladdr(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t buf[16];
	size_t len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_IPV6_LL_ADDR, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get LL_ADDR: %d", rv);
		return rv;
	}
	if (len < 16) {
		nn_osal_shell_error(sh, "short LL_ADDR (%zu)", len);
		return -EIO;
	}
	print_ipv6(sh, "LL", buf);
	return 0;
}

/*
 * IPV6_ADDRESS_TABLE is `A(t(6CLL))`: repeat of length-prefixed structs
 * each 16-byte addr + 1-byte prefix-len + 4-byte preferred + 4-byte valid.
 * Each struct is prefixed by its own uint16 length (little-endian).
 */
static int cmd_ncp_sync(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int a = ncp_netif_sync_addresses();
	int r = ncp_netif_sync_routes();
	nn_osal_shell_print(sh, "sync: addrs=%d routes=%d", a, r);
	return 0;
}

#include <zephyr/net/socket.h>
static int cmd_ncp_testraw(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int s = zsock_socket(NET_AF_INET, NET_SOCK_RAW, NET_IPPROTO_ICMP);
	nn_osal_shell_print(sh, "socket() = %d errno=%d", s, errno);
	if (s < 0) return s;
	/* Build a minimal ICMP Echo Request (type=8, code=0, id=0x1234, seq=1) */
	uint8_t icmp[16] = {
		8, 0, 0, 0,                    /* type, code, csum */
		0x12, 0x34, 0x00, 0x01,         /* id, seq */
		't','e','s','t','-','n','n',0,  /* payload */
	};
	uint32_t c = 0;
	for (int i = 0; i + 1 < (int)sizeof(icmp); i += 2) {
		c += ((uint16_t)icmp[i] << 8) | icmp[i + 1];
	}
	while (c >> 16) c = (c & 0xffff) + (c >> 16);
	c = ~c & 0xffff;
	icmp[2] = (c >> 8) & 0xff;
	icmp[3] = c & 0xff;

	struct net_sockaddr_in dst = {
		.sin_family = NET_AF_INET,
		.sin_port = 0,
	};
	/* 8.8.8.8 */
	uint8_t bytes[4] = {8, 8, 8, 8};
	memcpy(&dst.sin_addr, bytes, 4);
	ssize_t n = zsock_sendto(s, icmp, sizeof(icmp), 0,
				 (struct net_sockaddr *)&dst, sizeof(dst));
	nn_osal_shell_print(sh, "sendto() = %d errno=%d", (int)n, errno);
	zsock_close(s);
	return 0;
}

/*
 * Wrap an OT net-data change between
 *   SET THREAD_ALLOW_LOCAL_NET_DATA_CHANGE = true
 *   ...mutations...
 *   SET THREAD_ALLOW_LOCAL_NET_DATA_CHANGE = false
 * (required by OT — outside a "change window" INSERT returns invalid-state).
 */
static int netdata_mutate(int (*mutate)(uint32_t *ls), uint32_t *last_status)
{
	int rv = ncp_link_set_bool(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
				   true, SET_TIMEOUT);
	if (rv < 0) {
		return rv;
	}
	rv = mutate(last_status);
	/* End the change window regardless — pushes registration to leader. */
	(void)ncp_link_set_bool(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
				false, SET_TIMEOUT);
	return rv;
}

/*
 * Publish an Off-Mesh-Routable prefix via THREAD_ON_MESH_NETS with
 * SLAAC + ON_MESH + PREFERRED flags.  Sensors on the mesh will
 * auto-configure addresses in this prefix and use those (not their
 * mesh-local addresses) as the source for external traffic,
 * satisfying OT's `IsMeshLocalAddress(source)` drop check in
 * Ip6::PassToHost().
 *
 * ON_MESH_NETS entry layout `6CbCbSC`:
 *   `6` 16-byte prefix
 *   `C` prefix length
 *   `b` stable
 *   `C` TLV flags (SPINEL_NET_FLAG_* — ON_MESH|SLAAC|PREFERRED)
 *   `b` is defined locally
 *   `S` RLOC16 (0 for INSERT — NCP fills)
 *   `C` TLV flags extended (Thread 1.2+, 0)
 */
static int do_omr_insert(uint32_t *ls)
{
	uint8_t entry[] = {
		/* prefix: fdc0:face:b00c::/64 (locally-assigned ULA) */
		0xfd, 0xc0, 0xfa, 0xce, 0xb0, 0x0c, 0, 0,
		0,    0,    0,    0,    0,    0,    0, 0,
		64,          /* prefix len */
		1,           /* stable */
		0x31,        /* flags: ON_MESH | SLAAC | PREFERRED */
		1,           /* locally defined */
		0, 0,        /* RLOC16 (filled by NCP) */
		0,           /* extended flags */
	};
	return ncp_link_insert_raw(SPINEL_PROP_THREAD_ON_MESH_NETS,
				   entry, sizeof(entry), ls, SET_TIMEOUT);
}

static int do_omr_remove(uint32_t *ls)
{
	uint8_t entry[] = {
		0xfd, 0xc0, 0xfa, 0xce, 0xb0, 0x0c, 0, 0,
		0,    0,    0,    0,    0,    0,    0, 0,
		64,
	};
	return ncp_link_remove_raw(SPINEL_PROP_THREAD_ON_MESH_NETS,
				   entry, sizeof(entry), ls, SET_TIMEOUT);
}

static int cmd_ncp_omr_publish(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint32_t ls = 0;
	int rv = netdata_mutate(do_omr_insert, &ls);
	if (rv < 0) {
		nn_osal_shell_error(sh, "omr publish: rv=%d last-status=%u (%s)",
			    rv, ls, spinel_status_str(ls));
		return rv;
	}
	nn_osal_shell_print(sh, "omr publish: fdc0:face:b00c::/64 "
			"(ON_MESH|SLAAC|PREFERRED)");
	return 0;
}

static int cmd_ncp_omr_withdraw(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint32_t ls = 0;
	int rv = netdata_mutate(do_omr_remove, &ls);
	if (rv < 0) {
		nn_osal_shell_error(sh, "omr withdraw: rv=%d last-status=%u (%s)",
			    rv, ls, spinel_status_str(ls));
		return rv;
	}
	nn_osal_shell_print(sh, "omr withdraw: fdc0:face:b00c::/64 removed");
	return 0;
}

static int cmd_ncp_addrs(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	uint8_t buf[512];
	size_t  len = sizeof(buf);
	int rv = ncp_link_get(SPINEL_PROP_IPV6_ADDRESS_TABLE, buf, &len, GET_TIMEOUT);
	if (rv < 0) {
		nn_osal_shell_error(sh, "get ADDRESS_TABLE: %d", rv);
		return rv;
	}

	nn_osal_shell_print(sh, "addresses (%zu bytes):", len);
	size_t off = 0;
	int idx = 0;
	while (off + 2 <= len) {
		uint16_t slen = (uint16_t)buf[off] | ((uint16_t)buf[off + 1] << 8);
		off += 2;
		if (off + slen > len || slen < 16 + 1 + 4 + 4) {
			break;
		}
		const uint8_t *e = buf + off;
		uint8_t prefix = e[16];
		uint32_t pref = (uint32_t)e[17] | ((uint32_t)e[18] << 8) |
				((uint32_t)e[19] << 16) | ((uint32_t)e[20] << 24);
		uint32_t valid = (uint32_t)e[21] | ((uint32_t)e[22] << 8) |
				 ((uint32_t)e[23] << 16) | ((uint32_t)e[24] << 24);
		char str[NET_IPV6_ADDR_LEN];
		net_addr_ntop(NET_AF_INET6, e, str, sizeof(str));
		nn_osal_shell_print(sh, "  [%d] %s/%u  pref=%u valid=%u",
			    idx, str, prefix, pref, valid);
		off += slen;
		idx++;
	}
	return 0;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(ncp_subs,
	NN_OSAL_SHELL_CMD(version, cmd_ncp_version, "get NCP_VERSION"),
	NN_OSAL_SHELL_CMD(proto, cmd_ncp_proto, "get PROTOCOL_VERSION"),
	NN_OSAL_SHELL_CMD(caps, cmd_ncp_caps, "get CAPS"),
	NN_OSAL_SHELL_CMD(hwaddr, cmd_ncp_hwaddr, "get HWADDR"),
	NN_OSAL_SHELL_CMD(raw-get, cmd_ncp_raw_get, "GET <prop-id>; hex dump"),
	NN_OSAL_SHELL_CMD(raw-set, cmd_ncp_raw_set, "SET <prop-id> <hex-bytes>"),
	NN_OSAL_SHELL_CMD(stats, cmd_ncp_stats, "show link counters"),
	/* Thread bring-up (M-B1) */
	NN_OSAL_SHELL_CMD(ifconfig, cmd_ncp_ifconfig, "up|down — NET_IF_UP"),
	NN_OSAL_SHELL_CMD(thread, cmd_ncp_thread, "start|stop — NET_STACK_UP"),
	NN_OSAL_SHELL_CMD(role, cmd_ncp_role, "get NET_ROLE"),
	NN_OSAL_SHELL_CMD(state, cmd_ncp_state, "if-up/stack-up/role summary"),
	NN_OSAL_SHELL_CMD(channel, cmd_ncp_channel, "<11-26> — PHY_CHAN"),
	NN_OSAL_SHELL_CMD(panid, cmd_ncp_panid, "<0xNNNN> — MAC PANID"),
	NN_OSAL_SHELL_CMD(netname, cmd_ncp_netname, "<name> — NETWORK_NAME"),
	NN_OSAL_SHELL_CMD(xpanid, cmd_ncp_xpanid, "<hex16> — XPANID (8 B)"),
	NN_OSAL_SHELL_CMD(netkey, cmd_ncp_netkey, "<hex32> — NETWORK_KEY (16 B)"),
	NN_OSAL_SHELL_CMD(mladdr, cmd_ncp_mladdr, "get Mesh-Local addr"),
	NN_OSAL_SHELL_CMD(lladdr, cmd_ncp_lladdr, "get Link-Local addr"),
	NN_OSAL_SHELL_CMD(addrs, cmd_ncp_addrs, "get IPV6_ADDRESS_TABLE"),
	/* M-B3: mirror addresses and on-mesh prefixes onto local iface */
	NN_OSAL_SHELL_CMD(sync, cmd_ncp_sync, "sync NCP addrs + on-mesh routes"),
	NN_OSAL_SHELL_CMD(testraw, cmd_ncp_testraw, "test raw icmp sock send to 8.8.8.8"),
	NN_OSAL_SHELL_CMD(omr-publish, cmd_ncp_omr_publish, "publish OMR prefix fdc0:face:b00c::/64"),
	NN_OSAL_SHELL_CMD(omr-withdraw, cmd_ncp_omr_withdraw, "remove OMR prefix"),
	NN_OSAL_SHELL_SUBCMD_SET_END
);
NN_OSAL_SHELL_CMD_REGISTER_SET(ncp, &ncp_subs, NULL, "NCP host shell");

/* ── Autonomous boot sequence ────────────────────────────────────────── */

#include <nn_pal/wifi.h>

static K_SEM_DEFINE(wifi_up_sem, 0, 1);

static void wifi_pal_cb(nn_pal_wifi_event_t ev,
			const nn_pal_wifi_state_t *st, void *user)
{
	NN_OSAL_UNUSED(user);
	switch (ev) {
	case NN_PAL_WIFI_EV_CONNECTED:
		NN_LOG_INF("auto: wifi connected");
		k_sem_give(&wifi_up_sem);
		break;
	case NN_PAL_WIFI_EV_DISCONNECTED:
		NN_LOG_WRN("auto: wifi disconnected/failed (reason=%d) — "
			"driver-level reconnect + our watchdog will retry",
			st ? st->disconnect_reason : -1);
		break;
	default:
		break;
	}
}

/* WiFi reconnect watchdog — runs every 15 s.  If we lose WiFi and the
 * driver-level reconnect has stalled, re-issue NET_REQUEST_WIFI_CONNECT
 * with the saved credentials.  Idempotent: skipped while WiFi is up. */
static void wifi_watchdog_work(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_wifi_wd_work, wifi_watchdog_work);
/* Driver-level RECONNECT handles short retries.  Our watchdog is the
 * outer safety net, so it can be much sleepier — every 60 s. */
#define WIFI_WD_INTERVAL  K_SECONDS(60)

static void wifi_watchdog_work(struct k_work *w)
{
	NN_OSAL_UNUSED(w);
	if (nn_pal_wifi_is_connected()) {
		goto resched;
	}
	const char *ssid = gw_provision_get_ssid();
	const char *psk  = gw_provision_get_psk();
	if (!ssid || !psk) {
		goto resched;
	}
	NN_LOG_INF("wifi watchdog: re-issuing connect to \"%s\"", ssid);
	int rv = nn_pal_wifi_connect(ssid, psk);
	if (rv < 0) {
		NN_LOG_WRN("wifi watchdog: connect rv=%d", rv);
	}
resched:
	k_work_reschedule(&s_wifi_wd_work, WIFI_WD_INTERVAL);
}

static int auto_wifi_connect(void)
{
	const char *ssid = gw_provision_get_ssid();
	const char *psk  = gw_provision_get_psk();
	if (!ssid || !psk) {
		NN_LOG_ERR("auto: WiFi creds not provisioned — run "
			"`provision set <ssid> <psk> <hub_mdns> <hub_id_hex> <hub_pub_hex>`");
		return -EAGAIN;
	}
	(void)nn_pal_wifi_init(wifi_pal_cb, NULL);
	/* Arm the reconnect watchdog so a later AP drop doesn't strand us. */
	k_work_reschedule(&s_wifi_wd_work, WIFI_WD_INTERVAL);
	NN_LOG_INF("auto: wifi connect \"%s\"", ssid);
	int rv = nn_pal_wifi_connect(ssid, psk);
	if (rv < 0) {
		NN_LOG_ERR("auto: wifi connect: %d", rv);
		return rv;
	}
	if (k_sem_take(&wifi_up_sem, K_SECONDS(30)) < 0) {
		NN_LOG_ERR("auto: wifi timeout");
		return -ETIMEDOUT;
	}
	return 0;
}

static int auto_ncp_thread_start(void)
{
	/* Push the hub-supplied OT operational dataset into the NCP
	 * (channel, panid, extpanid, network key, network name, ML
	 * prefix) before flipping NET_IF_UP — otherwise the NCP would
	 * use whatever creds it had baked-in or learned previously. */
	size_t ot_len = 0;
	const uint8_t *ot_tlvs = gw_provision_get_ot_dataset(&ot_len);
	if (ot_tlvs && ot_len) {
		int arv = gw_ot_apply_dataset(ot_tlvs, ot_len);
		if (arv) {
			NN_LOG_WRN("gw_ot_apply_dataset rv=%d (continuing — "
				"NCP will use any pre-existing creds)", arv);
		}
	} else {
		NN_LOG_WRN("no OT dataset provisioned — NCP will use its own");
	}

	uint32_t ls = 0;
	uint8_t up_arg = 1;
	int rv = ncp_link_set_raw(SPINEL_PROP_NET_IF_UP, &up_arg, 1, &ls,
				  K_MSEC(2000));
	if (rv < 0) { NN_LOG_ERR("auto: NET_IF_UP: %d", rv); return rv; }
	rv = ncp_link_set_raw(SPINEL_PROP_NET_STACK_UP, &up_arg, 1, &ls,
			      K_MSEC(2000));
	if (rv < 0) { NN_LOG_ERR("auto: NET_STACK_UP: %d", rv); return rv; }
	NN_LOG_INF("auto: NCP thread started");
	return 0;
}

static int auto_wait_for_leader(void)
{
	/* Poll NET_ROLE every 2 s up to 60 s, wait for role=leader(3). */
	for (int i = 0; i < 30; i++) {
		k_sleep(K_SECONDS(2));
		uint8_t buf[4];
		size_t len = sizeof(buf);
		if (ncp_link_get(SPINEL_PROP_NET_ROLE, buf, &len,
				 K_MSEC(1000)) < 0 || len < 1) {
			continue;
		}
		NN_LOG_INF("auto: role=%u", buf[0]);
		if (buf[0] == 3) {  /* LEADER */
			return 0;
		}
	}
	NN_LOG_WRN("auto: leader not reached, continuing anyway");
	return -ETIMEDOUT;
}

static int auto_publish(void)
{
	uint32_t ls = 0;
	int rv = netdata_mutate(do_omr_insert, &ls);
	if (rv < 0) {
		NN_LOG_ERR("auto: omr-publish rv=%d ls=%u", rv, ls);
	} else {
		NN_LOG_INF("auto: OMR fdc0:face:b00c::/64 published");
	}
	return 0;
}

/* Board-ID LED: RED on the host, GREEN on the NCP (set in ncp_esp32c6).
 * Drives the on-board WS2812 (GPIO 8) so you can visually pick out which
 * dev kit is which without consulting `udevadm` or shell prompts. */
static void id_led_red(void)
{
	const struct device *strip = DEVICE_DT_GET(DT_ALIAS(led_strip));
	if (!device_is_ready(strip)) {
		NN_LOG_WRN("id-led: strip not ready");
		return;
	}
	struct led_rgb pix = { .r = 0x40, .g = 0x00, .b = 0x00 };  /* dim red */
	int rv = led_strip_update_rgb(strip, &pix, 1);
	if (rv) {
		NN_LOG_WRN("id-led: update rv=%d", rv);
	} else {
		NN_LOG_INF("id-led: RED (HOST)");
	}
}

int main(void)
{
	NN_LOG_INF("ESP32-C6 NCP Host (autonomous)");
	id_led_red();
	(void)gw_provision_init();
	if (gw_identity_init() != 0) {
		NN_LOG_ERR("gw_identity_init failed — broker will be unsigned");
	}
	/* Arm the OTA confirm-on-health worker.  If we just booted into
	 * an unconfirmed (test-mode) image, this defers the call to
	 * boot_write_img_confirmed() until both uptime and TCP state
	 * indicate the new image is actually working — otherwise MCUboot
	 * reverts on the next reboot. */
	(void)gw_ota_init();
	(void)gw_peer_reset_init();  /* GPIO 19 → NCP EN, idle high */

	/* M3: only enable BLE provisioning when the gateway is NOT yet
	 * provisioned.  Once provisioned, the autonomous path takes over
	 * and gw_ble_provision_stop() is called after TBR ready (below).
	 * For unprovisioned gateways, BLE stays up indefinitely until a
	 * client COMMITs creds, which triggers sys_reboot → next boot
	 * goes online. */
	if (!gw_provision_is_complete()) {
		NN_LOG_INF("not provisioned — BLE provisioning advertising");
		(void)gw_ble_provision_start();
	}

	(void)gw_watchdog_init();
	int rv = ncp_link_init();
	if (rv < 0) {
		NN_LOG_ERR("ncp_link_init failed: %d", rv);
		return rv;
	}
	nn_osal_sleep_ms(300);
	rv = ncp_netif_init();
	if (rv < 0) {
		NN_LOG_ERR("ncp_netif_init failed: %d", rv);
	}
	(void)border_agent_init();
	nn_osal_sleep_ms(500);
	int a = ncp_netif_sync_addresses();
	int r = ncp_netif_sync_routes();
	NN_LOG_INF("initial mirror: addrs=%d routes=%d", a, r);

	/* Autonomous bring-up — no shell interaction needed. */
	if (auto_wifi_connect() == 0) {
		(void)auto_ncp_thread_start();
		(void)auto_wait_for_leader();
		(void)auto_publish();
		NN_LOG_INF("auto: TBR ready");
		/* Advertise the meshcop Border Agent over mDNS so external
		 * commissioners can discover this BR. */
		{
			(void)nn_pal_mdns_set_hostname(CONFIG_NET_HOSTNAME);
			nn_pal_mdns_service_t h;
			int srv = nn_pal_mdns_advertise("_meshcop._udp",
							49191,
							nn_meshcop_txt,
							ARRAY_SIZE(nn_meshcop_txt),
							&h);
			if (srv < 0) NN_LOG_WRN("mdns advertise: %d", srv);
		}
		/* Now WiFi is up and Thread prefixes are mirrored —
		 * advertise them on the LAN so hub-side hosts auto-install
		 * a route towards us (RFC 4191).  Verified end-to-end:
		 * Linux receives the RA, installs the route, and SLAACs
		 * a global IPv6 in the OMR prefix.  Last-mile L2 ND reply
		 * is still TBD — see memory/feedback_ncp_host_tbr_inbound.md. */
		ra_sender_start();

		/* Bring up the nn_proto broker: router + UDP listener + TCP
		 * client + gateway commands (HELLO multicast, hub-status). */
		extern void nn_proto_broker_start(void);
		nn_proto_broker_start();

		/* Provisioning is no longer needed at this point — WiFi+OT+
		 * TBR+broker are all up.  Tear down the BLE stack to reclaim
		 * RAM (~30KB) and reduce attack surface.  A factory_reset
		 * (or fresh flash) can re-enable BLE on next boot. */
		(void)gw_ble_provision_stop();
	} else {
		NN_LOG_ERR("auto: wifi failed — TBR inoperative");
	}
	return 0;
}
