#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_burst_process.h"
#include "netns.h"
#include "tlsmsg.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct tcp_send_check_sample_cfg {
	__u64 ktime;
	__u64 burstEnable;
	__u64 burstAvgWindowSize;
	__u64 burstWindowSizeNs;
	__u64 burstTriggerMult;
};

struct bpf_map_def __attribute__((section("maps"), used))
tcp_send_check_sampler = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tcp_send_check_sample_cfg),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
tcp_send_check_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ipv4_event),
	.max_entries = 1,
};

__attribute__((section(("kprobe/tcp_v4_send_check")), used)) int
event_tcp_v4_send_check(struct pt_regs *ctx)
{
	struct socketmap_value *process;
	struct msg_tls_ipv4 tuple;
	struct tcp_sock *tcp;
	struct net *netns;
	struct sock *skp;
	int zero = 0;
	struct execve_map_value *exec_process;

	skp = (void *)((ctx)->di);
	tcp = (struct tcp_sock *)skp;

	/* Collect socket tuple and process info, updating state so close
	 * event will read zero window stats. If sampling we push event
	 * to user space.
	 */
	probe_read(&tuple.saddr, sizeof(tuple.saddr),
		   _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr),
		   _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));

	tuple.remaining = 0;
	tuple.uid = 0;

	if (is_tuple_local(&tuple))
		tuple.uid = sock_netns(skp);

	process = lookup_socketmap(&tuple);
	if (process) {
		struct tcp_send_check_sample_cfg *cfg;
		u64 current_time_ns = ktime_get_ns();
		struct msg_ipv4_event *val;
		__u32 rcv_wnd;
		size_t size;

		/* Check for zero window event. On zero window events we want to
		 * do some extra accounting to report these events to user space.
		 */
		probe_read(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));
		if (!rcv_wnd)
			process->zero_window++;

		cfg = map_lookup_elem(&tcp_send_check_sampler, &zero);
		if (!cfg)
			return 0;
		if (!process->last_time) {
			process->last_time = current_time_ns;
			goto out;
		} else if (process->last_time + cfg->ktime > current_time_ns) {
			goto out;
		}

		process->last_time = current_time_ns;
		val = map_lookup_elem(&tcp_send_check_event_map, &zero);
		if (!val)
			goto out;

		*val = (struct msg_ipv4_event){
			.common.op = ISO_MSG_OP_IPV4_TCPSTATS,
			.common.size = sizeof(struct msg_ipv4_event),
			.common.ktime = current_time_ns,

			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,

			.tuple.saddr = tuple.saddr,
			.tuple.daddr = tuple.daddr,
			.tuple.dport = tuple.dport,
			.tuple.sport = tuple.sport,
			.socket_cookie = get_cookie(skp),
			.socket_flags = 0,
			.pad = 0,
		};
		probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
		get_socket_stats(skp, netns, process->zero_window, &val->stats);
		size = sizeof(struct msg_ipv4_event);
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				  size);
	out:
		if (cfg->burstEnable) {
			exec_process = execve_map_get(process->key.pid);
			if (exec_process && exec_process->key.pid != 0) {
				struct process_network_burst_config c = {
					.avg_window_size_ms =
						cfg->burstAvgWindowSize,
					.window_size = cfg->burstWindowSizeNs,
					.trigger_mult = cfg->burstTriggerMult,
				};
				u64 tcp_bytes_sent, tcp_bytes_received;
				probe_read(&tcp_bytes_sent, sizeof(__u64),
					   _(&(tcp->bytes_sent)));
				probe_read(&tcp_bytes_received, sizeof(__u64),
					   _(&(tcp->bytes_received)));
				if (tcp_bytes_sent > process->sent) {
					process_network_burst(
						ctx, exec_process, IPPROTO_TCP,
						BURST_KEY_SEND_EGRESS,
						tcp_bytes_sent - process->sent,
						&c);
					process->sent = tcp_bytes_sent;
				}
				if (tcp_bytes_received > process->received) {
					process_network_burst(
						ctx, exec_process, IPPROTO_TCP,
						BURST_KEY_SEND_INGRESS,
						tcp_bytes_received -
							process->received,
						&c);
					process->received = tcp_bytes_received;
				}
			}
		}
	}
	return 1;
}
