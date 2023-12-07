#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup/post_bind4"), used)) int
tg_udp_bind_dummy4(struct pt_regs *ctx)
{
	return SK_PASS;
}

__attribute__((section("cgroup/post_bind6"), used)) int
tg_udp_bind_dummy6(struct pt_regs *ctx)
{
	return SK_PASS;
}
