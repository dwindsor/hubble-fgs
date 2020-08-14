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

__attribute__((section(("tracepoint/sys_exit")), used))
int event_exit(struct sched_execve_args *ctx)
{
	struct execve_map_value *enter;
	__u32 pid;

	pid = get_current_pid_tgid() & 0xFFFFffff;
	enter = map_lookup_event(pid);
	if (!enter)
		return 0;
	if (enter->key.ktime) {
		size_t size = sizeof(struct msg_exit);
		struct msg_exit exit;

		exit.common.op = MSG_OP_EXIT;
		exit.common.flags = 0;
		exit.common.pad[0] = 0;
		exit.common.pad[1] = 0;
		exit.common.size = size;
		exit.common.ktime = ktime_get_ns();

		exit.current.pid = pid;
		exit.current.pad[0] = 0;
		exit.current.pad[1] = 0;
		exit.current.pad[2] = 0;
		exit.current.pad[3] = 0;
		exit.current.ktime = enter->key.ktime;
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &exit, size);
	}
	map_delete_event(pid);
	return 0;
}
