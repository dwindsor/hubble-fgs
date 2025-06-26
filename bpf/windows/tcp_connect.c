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

struct msg_common {
	uint8_t op;
	uint8_t flags; // internal flags not exported
	uint8_t pad[2];
	uint32_t size;
	uint64_t ktime;
};

struct msg_ip_tuple {
	uint64_t saddr[2];
	uint64_t daddr[2];
	uint16_t dport;
	uint16_t sport;
	uint8_t proto;
	uint8_t send;
	uint8_t version_byte;
	uint8_t ipv6;
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_key {
	uint32_t pid; // Process TGID
	uint8_t pad[4];
	uint64_t ktime;
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	uint64_t socket_cookie;
	uint32_t socket_flags;
	uint32_t pad;
	uint64_t version;
	uint64_t ps_version; // pseudo-socket version (used in UDP).
	uint64_t create_time; // only used on close events.
	uint64_t close_time; // only used on close events.
}; // All fields aligned so no 'packed' attribute.

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