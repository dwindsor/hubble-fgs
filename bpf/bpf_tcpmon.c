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

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg = 0;
	struct sock *skp;
	bool walker = 0;
	__u32 ppid = 0;
	uint64_t size;

	msg = event_find_curr(&ppid, &msg_ipv4_tcp_map, &walker);
	if (!msg)
		return 0;

	skp = (void *)((ctx)->di);
	probe_read(&msg->tuple.proto, sizeof(msg->tuple.proto), &(skp->__sk_common.skc_family));
	probe_read(&msg->tuple.saddr, sizeof(msg->tuple.saddr), &(skp->__sk_common.skc_rcv_saddr));
	probe_read(&msg->tuple.daddr, sizeof(msg->tuple.daddr), &(skp->__sk_common.skc_daddr));
	probe_read(&msg->tuple.dport, sizeof(msg->tuple.dport), &(skp->__sk_common.skc_dport));
	probe_read(&msg->tuple.sport, sizeof(msg->tuple.sport), &(skp->__sk_common.skc_num));

	event_get_task_info(msg, MSG_OP_IPV4_TCPCONNECT, walker);
	size = validate_msg_size(msg->common.size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return 1;
}
