// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/tcp_v4_send_check"), used)) int
tg_event_tcp_v4_send_check(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
	return __event_tcp_send_check(ctx, skp, false);
}

__attribute__((section("kprobe/inet6_csk_xmit"), used)) int
tg_event_tcp_v6_send_check(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
	return __event_tcp_send_check(ctx, skp, true);
}
