
#include "compiler.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"
#include "process.h"
#include "process_endpoint.h"
#include "tcp_connect.h"
#include "process_tree.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct connection_key);
	__type(value, struct connection_entry);
	__uint(max_entries, 64 * 1024);
} connection_map SEC(".maps");

FUNC_INLINE bool bpf_udp_enabled(void)
{
	int zero = 0;
	struct cfg_value *cfg;

	cfg = (struct cfg_value *)bpf_map_lookup_elem(&tg_l3_cfg, &zero);
	return (cfg && cfg->udp_enabled);
}

uint16_t swap_bytes(uint16_t in)
{
	return (in << 8) | (in >> 8);
}

FUNC_INLINE void
get_event_from_ctx(bpf_sock_addr_t *ctx, int event_code, int ipv6, int is_accept, struct msg_ip_event *event)
{
	uint64_t ptid = bpf_get_current_pid_tgid();
	event->common.op = event_code;
	event->socket_cookie = bpf_get_socket_cookie(ctx);
	event->common.ktime = bpf_ktime_get_boot_ns();
	event->key.pid = ptid >> 32;

	uint64_t *daddr, *saddr;
	uint16_t *sport, *dport;

	if (is_accept) {
		daddr = &event->tuple.saddr[0];
		saddr = &event->tuple.daddr[0];
		sport = &event->tuple.dport;
		dport = &event->tuple.sport;
	} else {
		daddr = &event->tuple.daddr[0];
		saddr = &event->tuple.saddr[0];
		sport = &event->tuple.sport;
		dport = &event->tuple.dport;
	}

	if (ipv6) {
		__builtin_memcpy(daddr, ctx->user_ip6, sizeof(ctx->user_ip6));
		__builtin_memcpy(saddr, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
		event->tuple.ipv6 = 1;
	} else {
		__builtin_memcpy(daddr, (void *)(&ctx->user_ip4), sizeof(ctx->user_ip4));
		__builtin_memcpy(saddr, (void *)(&ctx->msg_src_ip4), sizeof(ctx->msg_src_ip4));
	}
	*sport = swap_bytes(ctx->msg_src_port);
	*dport = swap_bytes(ctx->user_port);

	event->tuple.proto = ctx->protocol;
	event->socket_flags = (event_code == 2) ? SOCKFLAGS_TYPE_CONNECT : SOCKFLAGS_TYPE_ACCEPT;
}

FUNC_INLINE uint64_t
allow_connection(struct msg_ip_tuple *tuple, uint64_t pid)
{
	int verdict = __process_socketmap_add(tuple, pid);

	return (!(verdict & TNP_POLICY_DENY));
}

FUNC_INLINE int
raise_ip_event(struct msg_ip_event *event)
{
	struct connection_entry entry = { 0 };
	struct connection_key key = { 0 };

	bpf_ringbuf_output(&process_ringbuf, event, sizeof(struct msg_ip_event), 0);
	key.pid = event->key.pid;
	__builtin_memcpy(&key.daddr, event->tuple.daddr, sizeof(event->tuple.daddr));
	key.dport = event->tuple.dport;
	key.sport = event->tuple.sport;
	entry.socket_cookie = event->socket_cookie;
	entry.socket_flags = event->socket_flags;
	bpf_map_update_elem(&connection_map, &key, &entry, BPF_ANY);
	return true;
}

SEC("cgroup/connect4")
int tcp_connect4(bpf_sock_addr_t *ctx)
{
	int event_code = 0;

	if (ctx->protocol == IPPROTO_TCP)
		event_code = 2;
	else if ((ctx->protocol == IPPROTO_UDP) && bpf_udp_enabled())
		event_code = 18;
	else
		return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

	struct msg_ip_event event = { 0 };
	uint64_t pid;

	get_event_from_ctx(ctx, event_code, 0, 0, &event);
	if (!allow_connection(&event.tuple, event.key.pid))
		return BPF_SOCK_ADDR_VERDICT_REJECT;

	raise_ip_event(&event);
	return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/connect6")
int tcp_connect6(bpf_sock_addr_t *ctx)
{
	int event_code = 0;

	if (ctx->protocol == IPPROTO_TCP)
		event_code = 2;
	else if ((ctx->protocol == IPPROTO_UDP) && bpf_udp_enabled())
		event_code = 18;
	else
		return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;

	uint64_t pid;
	struct msg_ip_event event = { 0 };

	get_event_from_ctx(ctx, event_code, 1, 0, &event);
	if (!allow_connection(&event.tuple, event.key.pid))
		return BPF_SOCK_ADDR_VERDICT_REJECT;

	raise_ip_event(&event);
	return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/recv_accept4")
int tcp_accept4(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
	uint64_t pid;
	struct msg_ip_event event = { 0 };

	get_event_from_ctx(ctx, 9, 0, 1, &event);

	raise_ip_event(&event);
	return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("cgroup/recv_accept6")
int tcp_accept6(bpf_sock_addr_t *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
	uint64_t pid;
	struct msg_ip_event event = { 0 };

	get_event_from_ctx(ctx, 9, 1, 1, &event);

	raise_ip_event(&event);
	return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

SEC("sockops")
int sockops_monitor(bpf_sock_ops_t *ctx)
{
	int event_code = 0;

	if (ctx->protocol == IPPROTO_TCP)
		event_code = 8;
	else if ((ctx->protocol == IPPROTO_UDP) && bpf_udp_enabled())
		event_code = 17;
	else
		return 0;
	int result = 0;
	uint64_t ptid = bpf_get_current_pid_tgid();
	struct msg_ip_with_stats_event event = { 0 };

	event.common.op = event_code;
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

	struct connection_entry *entry;
	struct connection_key key = { 0 };

	key.pid = event.key.pid;
	__builtin_memcpy(&key.daddr, event.tuple.daddr, sizeof(event.tuple.daddr));
	key.dport = event.tuple.dport;
	key.sport = event.tuple.sport;
	entry = bpf_map_lookup_elem(&connection_map, &key);
	if (entry) {
		event.socket_cookie = entry->socket_cookie;
		event.socket_flags = entry->socket_flags;
		bpf_map_delete_elem(&connection_map, &key);
	}

	bpf_ringbuf_output(&process_ringbuf, &event, sizeof(event), 0);
	return result;
}
