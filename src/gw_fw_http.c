/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

#include <zephyr/net/socket.h>

#include <nn_osal/osal.h>

#include "gw_fw_http.h"

NN_OSAL_LOG_MODULE(gw_fw_http);

#define HUB_FW_PORT      CONFIG_NN_PROTO_HUB_FW_PORT
#define LINE_BUF         256
#define HTTP_TIMEOUT_MS  30000

/* ── socket plumbing ───────────────────────────────────────────── */

static int resolve(const char *host, uint16_t port, struct sockaddr_in *out)
{
	struct zsock_addrinfo hints = {
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct zsock_addrinfo *res = NULL;
	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%u", port);

	int rv = zsock_getaddrinfo(host, port_str, &hints, &res);
	if (rv != 0 || !res) {
		NN_LOG_ERR("getaddrinfo(%s) -> %d", host, rv);
		return -EHOSTUNREACH;
	}
	memcpy(out, res->ai_addr, sizeof(*out));
	zsock_freeaddrinfo(res);
	return 0;
}

static int recv_line(int sock, char *out, size_t cap)
{
	size_t n = 0;
	while (n < cap - 1) {
		char ch;
		ssize_t got = zsock_recv(sock, &ch, 1, 0);
		if (got <= 0) {
			return (got == 0) ? -EIO : -errno;
		}
		if (ch == '\r') continue;
		if (ch == '\n') break;
		out[n++] = ch;
	}
	out[n] = 0;
	return (int)n;
}

/* Slurp a response body of known length up to `cap` bytes. */
static int slurp(int sock, char *dst, size_t cap, long content_length)
{
	long want = content_length < (long)cap ? content_length : (long)(cap - 1);
	long got = 0;
	while (got < want) {
		ssize_t n = zsock_recv(sock, dst + got, want - got, 0);
		if (n <= 0) return -EIO;
		got += n;
	}
	dst[got] = 0;
	return (int)got;
}

int gw_fw_http_open_get(const char *host, uint16_t port, const char *uri,
			long *content_length, char *out_sha_hex,
			size_t sha_hex_cap)
{
	struct sockaddr_in dst;
	int rv = resolve(host, port, &dst);
	if (rv) return rv;

	int sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		return -errno;
	}
	struct zsock_timeval tv = {
		.tv_sec  = HTTP_TIMEOUT_MS / 1000,
		.tv_usec = (HTTP_TIMEOUT_MS % 1000) * 1000,
	};
	(void)zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)zsock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (zsock_connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		NN_LOG_ERR("connect: errno=%d", errno);
		zsock_close(sock);
		return -errno;
	}

	char req[256];
	int rlen = snprintf(req, sizeof(req),
		"GET %s HTTP/1.0\r\nHost: %s\r\n"
		"User-Agent: nn-gw-ota/1\r\nConnection: close\r\n\r\n",
		uri, host);
	if (rlen <= 0 || rlen >= (int)sizeof(req)) {
		zsock_close(sock); return -EMSGSIZE;
	}
	if (zsock_send(sock, req, rlen, 0) != rlen) {
		zsock_close(sock); return -EIO;
	}

	char line[LINE_BUF];
	int n = recv_line(sock, line, sizeof(line));
	if (n < 0) { zsock_close(sock); return n; }
	int status = 0;
	if (sscanf(line, "HTTP/1.%*d %d", &status) != 1 || status != 200) {
		NN_LOG_ERR("HTTP %s -> %s", uri, line);
		zsock_close(sock);
		return -EPROTO;
	}

	*content_length = -1;
	if (out_sha_hex) out_sha_hex[0] = 0;
	while (true) {
		n = recv_line(sock, line, sizeof(line));
		if (n < 0) { zsock_close(sock); return n; }
		if (n == 0) break;
		if (strncasecmp(line, "Content-Length:", 15) == 0) {
			*content_length = strtol(line + 15, NULL, 10);
		} else if (out_sha_hex && sha_hex_cap >= 65 &&
			   strncasecmp(line, "X-FW-Sha256:", 12) == 0) {
			const char *p = line + 12;
			while (*p == ' ' || *p == '\t') p++;
			strncpy(out_sha_hex, p, sha_hex_cap - 1);
			out_sha_hex[sha_hex_cap - 1] = 0;
		}
	}
	if (*content_length <= 0) {
		NN_LOG_ERR("missing/zero Content-Length for %s", uri);
		zsock_close(sock);
		return -EPROTO;
	}
	return sock;
}

/* ── manifest ──────────────────────────────────────────────────── */

int gw_fw_fetch_manifest(const char *host, const char *device_type,
			 const char *version, struct gw_fw_manifest *m)
{
	memset(m, 0, sizeof(*m));
	char uri[96];
	int n = snprintf(uri, sizeof(uri),
			 "/gw_firmware/%s/%s/meta", device_type, version);
	if (n <= 0 || n >= (int)sizeof(uri)) return -ENAMETOOLONG;

	long len = -1;
	int sock = gw_fw_http_open_get(host, HUB_FW_PORT, uri, &len, NULL, 0);
	if (sock < 0) return sock;

	char body[512];
	int rv = slurp(sock, body, sizeof(body), len);
	zsock_close(sock);
	if (rv < 0) return rv;

	/* Helper: locate key, then skip ":" and whitespace.  Returns pointer
	 * positioned at the first non-whitespace byte of the value, or NULL.
	 * `expect_quote` requires the value to start with " for string types. */
	#define FIND_KEY(body, key, expect_quote, out_ptr) do {              \
		out_ptr = NULL;                                              \
		const char *_p = strstr((body), "\"" key "\"");              \
		if (_p) {                                                    \
			_p += strlen(key) + 2;                               \
			while (*_p == ' ' || *_p == '\t') _p++;              \
			if (*_p == ':') {                                    \
				_p++;                                        \
				while (*_p == ' ' || *_p == '\t') _p++;      \
				if (!(expect_quote) || *_p == '"') {         \
					out_ptr = (expect_quote) ? _p + 1 : _p; \
				}                                            \
			}                                                    \
		}                                                            \
	} while (0)

	const char *p;
	FIND_KEY(body, "type", true, p);
	if (p) {
		const char *q = strchr(p, '"');
		if (q && (q - p) < (int)sizeof(m->type)) {
			memcpy(m->type, p, q - p);
			m->type[q - p] = 0;
		}
	}
	FIND_KEY(body, "version", true, p);
	if (p) {
		const char *q = strchr(p, '"');
		if (q && (q - p) < (int)sizeof(m->version)) {
			memcpy(m->version, p, q - p);
			m->version[q - p] = 0;
		}
	}
	FIND_KEY(body, "size", false, p);
	if (p) {
		m->size = strtol(p, NULL, 10);
	}
	FIND_KEY(body, "sha256", true, p);
	if (p && strlen(p) >= 64) {
		for (int i = 0; i < 32; i++) {
			unsigned int b;
			if (sscanf(p + 2 * i, "%2x", &b) != 1) {
				return -EINVAL;
			}
			m->sha256[i] = (uint8_t)b;
		}
		m->sha256_valid = true;
	}
	#undef FIND_KEY

	if (strcmp(m->type, device_type) != 0 ||
	    strcmp(m->version, version) != 0 ||
	    m->size <= 0 || !m->sha256_valid) {
		NN_LOG_ERR("manifest fields invalid: type=%s ver=%s size=%ld",
			m->type, m->version, m->size);
		return -EPROTO;
	}
	return 0;
}

/* ── SHA-256 streaming ────────────────────────────────────────── */

int gw_fw_sha256_init(psa_hash_operation_t *op)
{
	*op = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
	psa_status_t rc = psa_hash_setup(op, PSA_ALG_SHA_256);
	if (rc != PSA_SUCCESS) {
		NN_LOG_ERR("psa_hash_setup: %d", rc);
		return -EIO;
	}
	return 0;
}

int gw_fw_sha256_update(psa_hash_operation_t *op,
			const uint8_t *chunk, size_t len)
{
	psa_status_t rc = psa_hash_update(op, chunk, len);
	if (rc != PSA_SUCCESS) {
		NN_LOG_ERR("psa_hash_update: %d", rc);
		return -EIO;
	}
	return 0;
}

int gw_fw_sha256_finish(psa_hash_operation_t *op, uint8_t out[32])
{
	size_t got = 0;
	psa_status_t rc = psa_hash_finish(op, out, 32, &got);
	if (rc != PSA_SUCCESS || got != 32) {
		NN_LOG_ERR("psa_hash_finish: %d", rc);
		return -EIO;
	}
	return 0;
}
