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
