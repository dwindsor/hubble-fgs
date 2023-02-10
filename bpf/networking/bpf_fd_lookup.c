#include "bpf_fd_lookup.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/proc_task_name"), used)) int
kprobe_proc_task_name(struct pt_regs *ctx)
{
	__kprobe_proc_task_name(ctx);
	return 0;
}
