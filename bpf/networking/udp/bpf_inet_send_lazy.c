#define MISSING_PERFEVENT   1
#define TRACK_ICMP_FROM_SKB 1
#include "vmlinux.h"
#include "bpf_inet.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/egress"), used)) int
tg_inet_lazy_send(struct __sk_buff *skb)
{
	inet_handler_lazy(skb, 1);
	return SK_PASS;
}

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_inet_lazy_recv(struct __sk_buff *skb)
{
	inet_handler_lazy(skb, 0);
	return SK_PASS;
}
