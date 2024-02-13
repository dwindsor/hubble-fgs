// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"

#include "api.h"
#include "bpf_tcp_accept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/tcp_create_openreq_child"), used)) int
tg_event_tcp_accept(struct pt_regs *ctx)
{
	return __event_tcp_accept(ctx);
}

__attribute__((section("kretprobe/tcp_create_openreq_child"), used)) int
tg_event_tcp_accept_ret(struct pt_regs *ctx)
{
	return __event_tcp_accept_ret(ctx);
}
