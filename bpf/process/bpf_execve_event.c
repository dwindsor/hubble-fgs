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

__attribute__((section(("tracepoint/sys_execve")), used))
int event_execve(struct sched_execve_args *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_execve_event *event, *parent_event;
	struct event_execve *parent;
	bool walker = 0;
	uint64_t size;
	__u32 pid;
	unsigned short fileoff;

	pid = (get_current_pid_tgid() >> 32);
	event = map_lookup_event(pid);
	if (!event)
		return 0;
	parent = (struct event_execve *)event->pid;
	parent_event = event_find_parent();
	if (parent_event)
		event_copy_execve(parent,
				  (struct event_execve *)&parent_event->pid);
	else
		event_minimal_parent(parent, task);

	fileoff = ctx->filename & 0xFFFF;
	event_filename_builder(parent, pid, EVENT_EXECVE, (char *)ctx + fileoff);
	event_args_builder(event);
	compiler_barrier();
	__event_get_task_info(event, MSG_OP_EXECVE, walker, true);
	size = validate_msg_execve_size(event->common.size);
	if (event->common.flags)
		event_set_clone(parent);
	event->common.flags = 0;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 0;
}
