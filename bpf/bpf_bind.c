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

__attribute__((section(("kprobe/sys_bind")), used))
int event_bind(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg = 0;
	struct sockaddr_in *in_addr;
	bool walker = 0;
	__u32 ppid = 0;
	uint64_t size;

#define AF_UNSPEC 0
#define AF_INET 2

	msg = event_find_curr(&ppid, &msg_ipv4_tcp_map, &walker);
	if (!msg)
		return 0;

	probe_read(&in_addr, sizeof(in_addr), &ctx->si);
	if (in_addr) {
		__u8 family = 0;

		probe_read(&family, sizeof(family), &in_addr->sin_family);
		if (family == AF_INET || family == AF_UNSPEC) {
			probe_read(&msg->tuple.proto, sizeof(msg->tuple.proto), &(in_addr->sin_family));
			probe_read(&msg->tuple.saddr, sizeof(msg->tuple.saddr), &(in_addr->sin_addr.s_addr));
			probe_read(&msg->tuple.sport, sizeof(msg->tuple.sport), &(in_addr->sin_port));
		}
	}
	event_get_task_info(msg, MSG_OP_IPV4_BIND, walker);
	size = validate_msg_size(msg->common.size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return 1;
}
