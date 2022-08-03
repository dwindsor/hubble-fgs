#include "bpf_sock_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kretprobe/sk_alloc"), used)) int
sk_allocret(struct pt_regs *ctx)
{
	__sk_allocret(ctx, false);
	return 0;
}
