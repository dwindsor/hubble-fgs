#include "bpf_sock_release.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/__sk_free"), used)) int
sk_free_lazy(struct pt_regs *ctx)
{
	__sk_free(ctx, true);
	return 0;
}
