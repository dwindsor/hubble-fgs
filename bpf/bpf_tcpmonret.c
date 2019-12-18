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

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kretprobe/sys_connect")), used))
int event_ret_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg = 0;
	__u32 ppid = 0;
	uint64_t size;
	bool walker;
	__u32 pid;

	pid = (get_current_pid_tgid() >> 32);

	msg = event_find_curr(&ppid, &walker);
	if (!msg) {
		bpf_printk("pid could not find curr %u\n", pid);
		return 0;
	}

	/*
	if (msg->common.op == MSG_OP_UNDEF) {
		bpf_printk("pid msg op undef curr %u\n", pid);
		return 0;
	}
	*/

	msg->ret = ctx->ax;
	msg->common.op = MSG_OP_IPV4_TCPCONNECTRET;

	size = validate_msg_size(msg->common.size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	msg->common.op = MSG_OP_UNDEF;
	msg->ret = 0;
	return 0;
}
