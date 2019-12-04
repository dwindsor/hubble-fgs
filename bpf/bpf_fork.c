#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/sys_fork")), used))
int event_fork(struct pt_regs *__ctx)
{
	struct msg_ipv4_tcp_connect *event;
	__u32 pid;

	pid = (get_current_pid_tgid() >> 32);
	event = map_lookup_event(pid);
	if (!event)
		return 0;
	event->common.size = 0;
	map_update_hash(event, pid);
	return 0;
}
