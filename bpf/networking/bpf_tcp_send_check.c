#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

struct tcp_send_check_sample_cfg {
	__u32 segs_cntr;
	__u32 segs_sample;
};

struct bpf_map_def __attribute__((section("maps"), used)) tcp_send_check_sampler = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tcp_send_check_sample_cfg),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) tcp_send_check_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ipv4_tcp_event),
	.max_entries = 1,
};

__attribute__((section(("kprobe/tcp_v4_send_check")), used))
int event_tcp_v4_send_check(struct pt_regs *ctx)
{
	struct socketmap_value *process;
	struct msg_tls_ipv4 tuple;
	struct tcp_sock *tcp;
	struct net *netns;
	struct sock *skp;
	__u32 rcv_wnd;
	int zero = 0;

	/* Stat events are generated using a sample rate, every N packets
	 * for now. This will favor noisy flows over quieter flows, but
	 * we probably want this anyways to provide more data about these
	 * types of flows. We can make a better algorithm if we want.
	 */
	struct tcp_send_check_sample_cfg *cfg;
	bool sample = false;

	cfg = map_lookup_elem(&tcp_send_check_sampler, &zero);
	if (!cfg)
		return 0;
	sample = !(cfg->segs_cntr++ % cfg->segs_sample);

	/* Check for zero window event. On zero window events we want to
	 * do some extra accounting to report these events to user space.
	 */
	skp = (void *)((ctx)->di);
	tcp = (struct tcp_sock *)skp;

	probe_read(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));
	if (rcv_wnd && !sample)
		return 1;

	/* Collect socket tuple and process info, updating state so close
	 * event will read zero window stats. If sampling we push event
	 * to user space.
	 */
	probe_read(&tuple.saddr, sizeof(tuple.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport), _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr), _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport), _(&(skp->__sk_common.skc_dport)));

	tuple.remaining = 0;
	tuple.uid = 0;

	probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
	if (netns) {
		struct ns_common *c = _(&netns->ns);

		probe_read(&tuple.uid, sizeof(c->inum), _(&c->inum));
	}

	if (!is_tuple_local(&tuple))
		tuple.uid = 0;
	process = lookup_socketmap(&tuple);
	if (process) {
		struct msg_ipv4_tcp_event *val;
		size_t size;

		if (!rcv_wnd)
			process->zero_window++;

		if (!sample)
			goto out;

		val = map_lookup_elem(&tcp_send_check_event_map, &zero);
		if (!val)
			return 1;

		*val = (struct msg_ipv4_tcp_event) {
			.common.op = MSG_OP_IPV4_TCPSTATS,
			.common.size = sizeof(struct msg_ipv4_tcp_event),
			.common.ktime = ktime_get_ns(),

			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,

			.tuple.saddr = tuple.saddr,
			.tuple.daddr = tuple.daddr,
			.tuple.dport = tuple.dport,
			.tuple.sport = tuple.sport,
			.socket_cookie = get_cookie(skp),
		};
		get_socket_stats(skp, netns, process->zero_window, &val->stats);
		size = sizeof(struct msg_ipv4_tcp_event);
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	}
out:
	return 1;
}
