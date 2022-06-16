#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"

#include "tls_map.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef TLS_TX
#define TLS_TX 1
#endif

#ifndef TLS_RX
#define TLS_RX 2
#endif

#define TLS_HTTPS (1 << 16)

struct bpf_map_def __attribute__((section("maps"), used)) https_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 128,
	.max_entries = 1,
};

static inline __attribute__((always_inline)) void
sockopt_tls_key(struct bpf_sockopt *ctx, struct msg_tls_ipv4 *key)
{
	struct bpf_sock *sk = ctx->sk;

	key->saddr = sk->src_ip4;
	key->daddr = sk->dst_ip4;
	key->dport = sk->dst_port;
	key->sport = sk->src_port;
	key->remaining = 0;
	key->uid = 0;
}

__attribute__((section("cgroup/setsockopt"), used)) int
setsockopt(struct bpf_sockopt *ctx)
{
	struct msg_tls_ipv4 key;
	struct msg_tls *event;

	/* In order to bypass kernel drop on optval>PAGE_SIZE set optlen = 0. */
	ctx->optlen = 0;

	if (ctx->level != SOL_TLS || ctx->optname != TLS_TX)
		return 1;

	sockopt_tls_key(ctx, &key);
	event = map_lookup_elem(&tls_map, &key);
	if (event) {
		struct sock_key filter_key = { 0 };
		int result;

		/* TLS filters are simple port base filters so we can
		 * skip more complex key extracting of addrs and cookies.
		 * Remembering to convert sport from network order to
		 * byte order to match filter format.
		 */
		filter_key.sport = bpf_ntohs(key.sport);
		filter_key.dport = key.dport;
		result = tls_filter(&filter_key);
		if (result & TLS_HTTPS)
			event->version = TLS_HTTP_VERSION;
	}
	return 1;
}
