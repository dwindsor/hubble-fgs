#include "vmlinux.h"
#include "bpf_icmp_rcv.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

// Handles received ICMP packets. We assume they are all linear and
// therefore can be read successfully with probe_read.
__attribute__((section("kprobe/icmp_rcv"), used)) int
tg_icmp_rcv(struct pt_regs *ctx)
{
	return icmp_rcv(ctx);
}

// Handles received ICMPv6 packets. We assume they are all linear and
// therefore can be read successfully with probe_read.
__attribute__((section("kprobe/icmpv6_rcv"), used)) int
tg_icmpv6_rcv(struct pt_regs *ctx)
{
	return icmp_rcv(ctx);
}
