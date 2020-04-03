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

__attribute__((section(("kprobe/sys_execve")), used))
int event_execve(struct pt_regs *__ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_ipv4_tcp_connect *event, *parent_event;
	struct xdp_buff *kver_pivot, __kver_pivot;
	struct event_execve *parent;
	struct pt_regs *ctx;
	int exists;
	__u32 pid;

	kver_pivot = &__kver_pivot;
	/* xdp_buff->handle was added in v4.18 so we use it to decide if
	 * we should use ctx pointer or not.
	 */
	exists = bpf_core_field_exists(kver_pivot->handle);
	if (exists) {
		ctx = (struct pt_regs *) __ctx->di;
	} else {
		ctx = __ctx;
	}

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

	event_filename_builder(parent, pid, EVENT_EXECVE, &ctx->di);
	event_args_builder(event, &ctx->si);
	event_cwd_builder(parent, pid);
	compiler_barrier();
	event->common.size = 1; // stand-in until we complete calculation from tcpmon
	return 0;
}
