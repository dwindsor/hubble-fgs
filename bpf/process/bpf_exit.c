#include "vmlinux.h"
#include "../../modules/tetragon-oss/bpf/process/bpf_exit.h"
#include "../networking/bpf_process_network_watermarks.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("tracepoint/sys_exit"), used)) int event_exit(struct sched_execve_args *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 pid = pid_tgid & 0xFFFFffff;
	__u32 tgid = pid_tgid >> 32;

	if (pid == tgid)
		process_watermarks_map_delete(ctx, tgid);
	event_exit_send(ctx, pid_tgid);
	return 0;
}
