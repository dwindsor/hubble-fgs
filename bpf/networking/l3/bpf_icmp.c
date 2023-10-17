#include "vmlinux.h"
#include "bpf_icmp.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_icmp_recv(struct __sk_buff *skb)
{
	icmp_handler(skb, false);
	return SK_PASS;
}

__attribute__((section("cgroup_skb/egress"), used)) int
tg_icmp_send(struct __sk_buff *skb)
{
	icmp_handler(skb, true);
	return SK_PASS;
}
