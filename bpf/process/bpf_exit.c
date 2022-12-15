#include "../../modules/tetragon-oss/bpf/process/bpf_exit.h"
#include "../networking/bpf_burst_process.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("tracepoint/sys_exit"), used)) int
event_exit(struct sched_execve_args *ctx)
{
	__u64 pid_tgid;

	pid_tgid = get_current_pid_tgid();

	process_burst_map_delete(ctx, pid_tgid);
	event_exit_send(ctx, pid_tgid);
	return 0;
}
