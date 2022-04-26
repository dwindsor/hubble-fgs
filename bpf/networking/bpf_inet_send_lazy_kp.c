#include "vmlinux.h"
#include "bpf_inet.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/__cgroup_bpf_run_filter_skb")), used)) int
inet_lazy_send_kp(struct pt_regs *ctx)
{
	struct sock *sk = (void *)ctx->di;
	struct sk_buff *skb = (void *)ctx->si;
	int bpf_attach_type = (int)ctx->dx;
	inet_handler_lazy_kp(ctx, sk, skb,
			     bpf_attach_type == BPF_CGROUP_INET_EGRESS);
	return 0;
}
