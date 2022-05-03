#include "vmlinux.h"
#include "bpf_inet.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("cgroup_skb/egress")), used)) int
inet_send(struct __sk_buff *skb)
{
	inet_handler(skb, 1);
	return SK_PASS;
}

__attribute__((section(("cgroup_skb/ingress")), used)) int
inet_recv(struct __sk_buff *skb)
{
	inet_handler(skb, 0);
	return SK_PASS;
}
