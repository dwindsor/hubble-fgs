#include "vmlinux.h"
#include "bpf_tcp_recv.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_tcp_recv_lazy(struct __sk_buff *skb)
{
	tcp_handler_lazy(skb);
	return SK_PASS;
}
