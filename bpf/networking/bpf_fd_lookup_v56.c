#include "bpf_fd_lookup.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/check_kill_permission"), used)) int
kprobe_check_kill_permission(struct pt_regs *ctx)
{
	__kprobe_check_kill_permission(ctx, false);
	return 0;
}
