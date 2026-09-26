/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>

#include <nn_osal/osal.h>
#include <nn_proto/nn_proto.h>

#include "proto_udp.h"

NN_OSAL_LOG_MODULE(proto_udp);

#define WORKER_STACK_SIZE 4096
#define WORKER_PRIO       6
#define RX_BUF_SIZE       1280     /* one Thread MTU frame */

/* Thread realm-local mcast: ff03::1 (all-nodes realm-local) */
static const struct in6_addr s_mcast_dst = {
	.s6_addr = { 0xff, 0x03, 0, 0,  0, 0, 0, 0,
		     0,    0,    0, 0,  0, 0, 0, 0x01 },
};

static struct {
	int                    fd;       /* recv socket bound to port */
	struct proto_udp_config cfg;
	struct proto_udp_stats stats;
} S;

K_THREAD_STACK_DEFINE(s_udp_stack, WORKER_STACK_SIZE);
static struct k_thread s_udp_worker;

/* ── helpers ────────────────────────────────────────────────────────────── */

/* Send a single datagram via a transient socket.  We could share the
 * recv socket, but Zephyr's UDP send-from-recv-socket has historically
 * been finicky around source-address selection on multi-interface hosts.
 * One transient socket per send keeps the path predictable. */
static int send_to(const struct in6_addr *dst, uint16_t port,
		   const uint8_t *frame, size_t len, bool mcast)
{
	int fd = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		NN_LOG_WRN("socket: %d", errno);
		S.stats.tx_failures++;
		return -errno;
	}
	if (mcast) {
		/* Outbound mcast hop limit: 1 (Thread realm-local). */
		int hop = 1;
		(void)zsock_setsockopt(fd, IPPROTO_IPV6,
				       IPV6_MULTICAST_HOPS, &hop, sizeof(hop));
	}

	struct sockaddr_in6 dst_sa = {
		.sin6_family = AF_INET6,
		.sin6_port   = htons(port),
	};
	memcpy(&dst_sa.sin6_addr, dst, sizeof(struct in6_addr));

	ssize_t n = zsock_sendto(fd, frame, len, 0,
				 (struct sockaddr *)&dst_sa, sizeof(dst_sa));
	zsock_close(fd);
	if (n < 0 || (size_t)n != len) {
		NN_LOG_WRN("sendto: rv=%zd errno=%d", n, errno);
		S.stats.tx_failures++;
		return -EIO;
	}
	if (mcast) S.stats.tx_mcast++;
	else       S.stats.tx_unicast++;
	return 0;
}

static void udp_worker(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	uint8_t buf[RX_BUF_SIZE];

	while (true) {
		struct sockaddr_in6 src;
		socklen_t           src_len = sizeof(src);

		ssize_t n = zsock_recvfrom(S.fd, buf, sizeof(buf), 0,
					   (struct sockaddr *)&src, &src_len);
		if (n < 0) {
			NN_LOG_WRN("recvfrom: errno=%d", errno);
			nn_osal_sleep_ms(100);
			continue;
		}
		if ((size_t)n > sizeof(buf)) {
			S.stats.rx_drops_oversize++;
			continue;
		}

		/* Validate magic + length consistency before dispatch. */
		struct nn_proto_view view;
		size_t consumed = 0;
		int rv = nn_proto_parse(buf, (size_t)n, &view, &consumed);
		if (rv != 0 || consumed != (size_t)n) {
			NN_LOG_WRN("rx parse: rv=%d (frame_len=%zd consumed=%zu)",
				rv, n, consumed);
			S.stats.rx_drops_bad++;
			continue;
		}
		S.stats.rx_frames++;
		S.stats.rx_bytes += (uint32_t)n;

		if (S.cfg.on_rx) {
			S.cfg.on_rx(buf, (size_t)n,
				    &src.sin6_addr, ntohs(src.sin6_port),
				    S.cfg.on_rx_user);
		}
	}
}

/* ── public API ─────────────────────────────────────────────────────────── */

int proto_udp_init(const struct proto_udp_config *cfg)
{
	if (!cfg || !cfg->port) {
		return -EINVAL;
	}
	S.cfg = *cfg;

	S.fd = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (S.fd < 0) {
		NN_LOG_ERR("socket: %d", errno);
		return -errno;
	}

	struct sockaddr_in6 sa = {
		.sin6_family = AF_INET6,
		.sin6_port   = htons(cfg->port),
		.sin6_addr   = in6addr_any,
	};
	if (zsock_bind(S.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		NN_LOG_ERR("bind: %d", errno);
		zsock_close(S.fd);
		S.fd = -1;
		return -errno;
	}

	k_thread_create(&s_udp_worker, s_udp_stack,
			K_THREAD_STACK_SIZEOF(s_udp_stack),
			udp_worker, NULL, NULL, NULL,
			WORKER_PRIO, 0, K_NO_WAIT);
	k_thread_name_set(&s_udp_worker, "proto_udp");

	NN_LOG_INF("proto_udp listening on UDP/%u", cfg->port);
	return 0;
}

int proto_udp_send_unicast(const struct in6_addr *dst, uint16_t dst_port,
			   const uint8_t *frame, size_t len)
{
	if (!dst || !frame || len == 0) {
		return -EINVAL;
	}
	return send_to(dst, dst_port, frame, len, false);
}

int proto_udp_send_mcast(const uint8_t *frame, size_t len)
{
	if (!frame || len == 0) {
		return -EINVAL;
	}
	return send_to(&s_mcast_dst, S.cfg.port, frame, len, true);
}

void proto_udp_get_stats(struct proto_udp_stats *out)
{
	if (out) *out = S.stats;
}
