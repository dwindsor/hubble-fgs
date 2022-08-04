#include "bpf_tcp_send_check.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/tcp_v4_send_check"), used)) int
event_tcp_v4_send_check(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *)((ctx)->di);
	return __event_tcp_send_check(ctx, skp, false);
}

__attribute__((section("kprobe/inet6_csk_xmit"), used)) int
event_tcp_v6_send_check(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *)((ctx)->di);
	return __event_tcp_send_check(ctx, skp, true);
}
