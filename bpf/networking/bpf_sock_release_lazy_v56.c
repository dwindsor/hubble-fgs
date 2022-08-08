#include "bpf_sock_release.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/inet_release"), used)) int
sock_release_lazy_v56(struct pt_regs *ctx)
{
	__sock_release(ctx, true, false);
	return 0;
}
