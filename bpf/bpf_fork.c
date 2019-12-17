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

__attribute__((section(("kprobe/wake_up_new_task")), used))
int event_wake_up_new_task(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *event;
	struct task_struct *task;
	u32 pid;

	probe_read(&task, sizeof(task), &ctx->di);
	if (!task)
		return 0;
	probe_read(&pid, sizeof(pid), &task->pid);

	event = map_lookup_event(pid);
	if (!event)
		return 0;
	event->common.size = 0;
	map_update_hash(event, pid);
	return 0;
}
