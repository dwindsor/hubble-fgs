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

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

__attribute__((section(("kprobe/tcp_set_state")), used))
int event_ipv4_close(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_event value;
	struct msg_execve_key *process;
	struct msg_tls_ipv4 tuple;
	struct sock *skp;
	size_t size;
	int state;


	state = ctx->si;
	if (state != TCP_CLOSE)
		return 0;

	skp = (void *)((ctx)->di);

	probe_read(&tuple.saddr, sizeof(tuple.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport), _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr), _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport), _(&(skp->__sk_common.skc_dport)));

	tuple.proto = 0;
	tuple.pad[0] = 0;
	tuple.pad[1] = 0;
	tuple.pad[2] = 0;

	value.common.op = MSG_OP_IPV4_TCPCLOSE;
	value.common.flags = 0;
	value.common.pad[0] = 0;
	value.common.pad[1] = 0;
	value.common.size = sizeof(struct msg_ipv4_tcp_event);
	value.common.ktime = ktime_get_ns();

	value.tuple.saddr = tuple.saddr;
	value.tuple.daddr = tuple.daddr;
	value.tuple.dport = tuple.dport;
	value.tuple.sport = tuple.sport;
	value.tuple.proto = 0;
	value.tuple.post_daddr = 0; // After bpf-cgroup rewrites
	value.tuple.post_dport = 0; // After bpf-cgroup rewrites
	value.tuple.pad[0] = 0;
	value.tuple.pad[1] = 0;
	value.tuple.pad[2] = 0;
	value.tuple.pad[3] = 0;
	value.tuple.pad[4] = 0;

	value.ret = 0; // Populated by kretprobe
	memset(value.key.pad, 0, sizeof(value.key.pad));

	process = lookup_socketmap(&tuple);
	if (process) {
		value.key.pid = process->pid;
		value.key.ktime = process->ktime;
	} else {
		value.key.pid = 0;
		value.key.ktime = 0;
	}

	size = sizeof(struct msg_ipv4_tcp_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &value, size);
	del_socketmap(&tuple);

	tuple.dport = bpf_htons(tuple.dport);
	map_delete_elem(&tls_map, &tuple);
	return 1;
}
