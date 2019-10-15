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

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
	unsigned int (*key_size)[sizeof(__u32)];
	unsigned int (*value_size)[sizeof(struct event_execve)];
	unsigned int (*max_entries)[1];
} execveat_map_store __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) execveat_map_store = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event_execve),
	.max_entries = 1,
};
#endif


char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("kprobe/sys_execveat")), used))
int event_execveat(struct pt_regs *__ctx)
{
#ifdef VMLINUX_KERNEL_HAS_SYSCALL_WRAPPER
	struct pt_regs *ctx = (struct pt_regs *) __ctx->di;
#else
	struct pt_regs *ctx = __ctx;
#endif
	struct event_execve *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execveat_map_store, &zero);
	if (!event)
		return 0;
	event->pid = (get_current_pid_tgid() >> 32);
	event_filename_builder(event, &ctx->si);
	event_filename_builder(event, &ctx->dx);
	map_update_elem(&execve_map, &event->pid, event, 0);
	return 0;
}
