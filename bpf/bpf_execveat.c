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

__attribute__((section(("kprobe/sys_execveat")), used))
int event_execveat(struct pt_regs *__ctx)
{
#ifdef VMLINUX_KERNEL_HAS_SYSCALL_WRAPPER
	struct pt_regs *ctx = (struct pt_regs *) __ctx->di;
#else
	struct pt_regs *ctx = __ctx;
#endif
	struct msg_ipv4_tcp_connect *event, *parent;
	__u32 pid;

	pid  = (get_current_pid_tgid() >> 32);
	event = map_lookup_elem(&execve_map, &pid);
	if (!event)
		return 0;
	event->pid.curr.pid = pid;
	event_filename_builder(&event->pid.curr, &ctx->si);
	event_args_builder(&event->pid.curr, &ctx->dx);
	parent = event_find_parent();
	if (!parent)
		return 0;
	event_copy_parent(event, parent);
	return 0;
}
