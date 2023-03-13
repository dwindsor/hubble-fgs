#include "vmlinux.h"
#include "bpf_inet.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/__cgroup_bpf_run_filter_skb"), used)) int
inet_lazy_send_kp(struct pt_regs *ctx)
{
	struct sock *sk = (void *)PT_REGS_PARM1_CORE(ctx);
	struct sk_buff *skb = (void *)PT_REGS_PARM2_CORE(ctx);
	int bpf_attach_type = (int)PT_REGS_PARM3_CORE(ctx);
	inet_handler_lazy_kp(ctx, sk, skb,
			     bpf_attach_type == BPF_CGROUP_INET_EGRESS);
	return 0;
}
