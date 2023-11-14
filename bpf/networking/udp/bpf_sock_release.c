#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "bpf_fd_lookup.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} udp_close_event_map SEC(".maps");

__attribute__((section("kprobe/udp_destroy_sock"), used)) int
tg_udp_destroy_sock(struct pt_regs *ctx)
{
	__u64 cookie = PT_REGS_PARM1(ctx);
	struct socketmap_value *process;
	struct msg_ip_event *event;
	int zero = 0;
	size_t size;

	event = (struct msg_ip_event *)map_lookup_elem(&udp_close_event_map, &zero);
	if (!event)
		return 0;

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	*event = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),
		.common.op = ISO_MSG_OP_UDPCLOSE,
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,

		.socket_cookie = cookie,
		.socket_flags = process->socket_flags,
		.pad = 0,
	};

	/* Fill in the current time as a place-holder for the duration. We will
	 * calculate the actual duration when we walk all the pseudo-sockets
	 * associated with this socket.
	 */
	event->duration = ktime_get_ns();

	event->tuple.ipv6 = 0;
	event->tuple.saddr[0] = 0;
	event->tuple.saddr[1] = 0;
	event->tuple.daddr[0] = 0;
	event->tuple.daddr[1] = 0;
	event->tuple.sport = 0;
	event->tuple.dport = 0;

	event->stats.ktime = 0;
	event->stats.bytes_sent = 0;
	event->stats.bytes_received = 0;
	event->stats.segs_out = 0;
	event->stats.segs_in = 0;
	event->stats.bytes_submitted = 0;
	event->stats.bytes_consumed = 0;
	event->stats.segs_submitted = 0;
	event->stats.segs_consumed = 0;
	event->stats.sk_drops = 0;
	event->stats.skb_consume_misses = 0;

	size = sizeof(struct msg_ip_event);
	perf_event_output_metric(ctx, ISO_MSG_OP_UDPCLOSE, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	del_socketmap(&cookie);
	return 1;
}
