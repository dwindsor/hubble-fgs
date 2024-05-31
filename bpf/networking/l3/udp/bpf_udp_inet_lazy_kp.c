// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#define IS_KPROBE 1
#include "vmlinux.h"
#include "bpf_udp_inet.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/__cgroup_bpf_run_filter_skb"), used)) int
tg_inet_lazy_send_kp(struct pt_regs *ctx)
{
	struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
	int bpf_attach_type = (int)PT_REGS_PARM3(ctx);
	struct sock *sk = (void *)PT_REGS_PARM1(ctx);

	if (bpf_attach_type == BPF_CGROUP_INET_EGRESS) {
		inet_handler_lazy_kp(ctx, sk, skb, 1);
	} else {
		inet_handler_lazy_kp(ctx, sk, skb, 0);
	}
	return 0;
}
