#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"

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

struct https_filter_map_data {
	char data[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct https_filter_map_data);
	__uint(max_entries, 1);
} https_filter_map SEC(".maps");

__attribute__((section("cgroup/setsockopt"), used)) int
tg_setsockopt(struct bpf_sockopt *ctx)
{
	struct msg_tls *event;
	struct bpf_sock *sk = ctx->sk;
	u64 *cookie;
	int zero = 0;

	/* In order to bypass kernel drop on optval>PAGE_SIZE set optlen = 0. */
	ctx->optlen = 0;

	if (ctx->level != SOL_TLS || ctx->optname != TLS_TX)
		return 1;

	cookie = map_lookup_elem(&tg_tls_cookie_heap, &zero);
	if (!cookie)
		return 1;

	*cookie = (u64)sk;
	if (!*cookie)
		return 1;

	event = map_lookup_elem(&tg_tls_map, cookie);
	if (event) {
		struct sock_key filter_key = { 0 };
		int result;

		/* TLS filters are simple port base filters so we can
		 * skip more complex key extracting of addrs and cookies.
		 * Remembering to convert sport from network order to
		 * byte order to match filter format.
		 */
		filter_key.sport = bpf_ntohs(sk->src_port);
		filter_key.dport = sk->dst_port;
		result = tls_filter(&filter_key);
		if (result & TLS_HTTPS)
			event->version = TLS_HTTP_VERSION;
	}
	return 1;
}
