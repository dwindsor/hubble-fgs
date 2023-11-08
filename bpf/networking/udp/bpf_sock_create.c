#include "vmlinux.h"

#include "api.h"
#include "bpf_sock_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/udp_init_sock"), used)) int
tg_udp_init_sock(struct pt_regs *ctx)
{
	return __tg_udp_init_sock(ctx);
}

__attribute__((section("kprobe/udpv6_init_sock"), used)) int
tg_udpv6_init_sock(struct pt_regs *ctx)
{
	return __tg_udp_init_sock(ctx);
}
