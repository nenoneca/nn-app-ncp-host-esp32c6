/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_fw_http — shared HTTP + manifest + sha256 helpers for both host
 * self-OTA (gw_ota.c) and the NCP relay path (ncp_ota_client.c).
 */

#ifndef GW_FW_HTTP_H_
#define GW_FW_HTTP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Manifest as parsed from /gw_firmware/<type>/<version>/meta. */
struct gw_fw_manifest {
	char    type[24];
	char    version[24];
	long    size;
	uint8_t sha256[32];
	bool    sha256_valid;
};

/* Pull the manifest JSON, parse, and validate that type/version match. */
int gw_fw_fetch_manifest(const char *host, const char *device_type,
			 const char *version, struct gw_fw_manifest *out);

/* Open a TCP connection to <host>:<port>, send GET <uri> HTTP/1.0, parse
 * response status + headers.  On success returns the connected socket
 * fd; *content_length is set; server's X-FW-Sha256 (if present) is
 * copied into out_sha_hex (must be ≥65B).  Caller closes the fd. */
int gw_fw_http_open_get(const char *host, uint16_t port, const char *uri,
			long *content_length, char *out_sha_hex,
			size_t sha_hex_cap);

/* SHA-256 streaming helpers wrapping psa_hash_*. */
int gw_fw_sha256_init(psa_hash_operation_t *op);
int gw_fw_sha256_update(psa_hash_operation_t *op,
			const uint8_t *chunk, size_t len);
int gw_fw_sha256_finish(psa_hash_operation_t *op, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* GW_FW_HTTP_H_ */
