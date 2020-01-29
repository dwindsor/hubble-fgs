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
	__u32 ppid = 0, pid = (get_current_pid_tgid() >> 32);
	struct msg_ipv4_tcp_connect *msg = 0;
	struct sockaddr_in *in_addr;
	bool walker = 0;

	msg = event_find_curr(&ppid, &msg_ipv4_tcp_map, &walker);
	if (!msg)
		return 0;

	probe_read(&in_addr, sizeof(in_addr), &ctx->si);
	if (in_addr) {
		probe_read(&msg->tuple.proto, sizeof(msg->tuple.proto), _(&in_addr->sin_family));
		probe_read(&msg->tuple.saddr, sizeof(msg->tuple.saddr), _(&in_addr->sin_addr.s_addr));
		probe_read(&msg->tuple.sport, sizeof(msg->tuple.sport), _(&in_addr->sin_port));
	}
	msg->common.size = 1; // stand-in until we complete calculation from listen
	map_update_hash(msg, pid);
	return 1;
}
