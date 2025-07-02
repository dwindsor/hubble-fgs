#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"
#include "tcp_connect.h"

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ringbuf SEC(".maps");

uint16_t swap_bytes(uint16_t in)
{
	return (in << 8) | (in >> 8);
}

__inline void
raise_ip_event(bpf_sock_addr_t *ctx, int eventCode, int ipv6)
{
	uint64_t ptid = bpf_get_current_pid_tgid();

	struct msg_ip_event event = { 0 };
	event.common.op = eventCode;
	event.socket_cookie = bpf_get_socket_cookie(ctx);
	event.common.ktime = bpf_ktime_get_boot_ns();
	event.key.pid = ptid >> 32;
	if (ipv6) {
		__builtin_memcpy(event.tuple.daddr, ctx->user_ip6, sizeof(ctx->user_ip6));
		__builtin_memcpy(event.tuple.saddr, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
		event.tuple.ipv6 = 1;
	} else {
		event.tuple.daddr[0] = ctx->user_ip4;
		event.tuple.saddr[0] = ctx->msg_src_ip4;
	}
	event.tuple.sport = swap_bytes(ctx->msg_src_port);
	event.tuple.dport = swap_bytes(ctx->user_port);
	event.tuple.proto = ctx->protocol;
	bpf_ringbuf_output(&process_ringbuf, &event, sizeof(event), 0);
}

SEC("cgroup/connect4")
int tcp_connect4(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP) {
		return BPF_SOCK_ADDR_VERDICT_PROCEED;
	}
	raise_ip_event(ctx, 2, 0);
	return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect6")
int tcp_connect6(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP) {
		return BPF_SOCK_ADDR_VERDICT_PROCEED;
	}
	raise_ip_event(ctx, 2, 1);
	return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/recv_accept4")
int tcp_accept4(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP) {
		return BPF_SOCK_ADDR_VERDICT_PROCEED;
	}
	raise_ip_event(ctx, 9, 0);
	return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/recv_accept6")
int tcp_accept6(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP) {
		return BPF_SOCK_ADDR_VERDICT_PROCEED;
	}
	raise_ip_event(ctx, 9, 1);
	return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("sockops")
int sockops_monitor(bpf_sock_ops_t *ctx)
{
	if ((ctx->protocol != IPPROTO_TCP) ||
	    (ctx->op != BPF_SOCK_OPS_CONNECTION_DELETED_CB)) {
		return 0;
	}
	int result = 0;
	uint64_t ptid = bpf_get_current_pid_tgid();

	struct msg_ip_with_stats_event event = { 0 };
	event.common.op = 8;
	event.socket_cookie = 0;
	event.common.ktime = bpf_ktime_get_boot_ns();
	event.key.pid = ptid >> 32;
	if (ctx->family == AF_INET) {
		event.tuple.daddr[0] = ctx->remote_ip4;
		event.tuple.saddr[0] = ctx->local_ip4;
	} else {
		__builtin_memcpy(event.tuple.daddr, ctx->remote_ip6, sizeof(ctx->remote_ip6));
		__builtin_memcpy(event.tuple.saddr, ctx->local_ip6, sizeof(ctx->local_ip6));
		event.tuple.ipv6 = 1;
	}
	event.tuple.sport = swap_bytes(ctx->local_port);
	event.tuple.dport = swap_bytes(ctx->remote_port);
	event.tuple.proto = ctx->protocol;
	bpf_ringbuf_output(&process_ringbuf, &event, sizeof(event), 0);
	return result;
}
