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
SEC("fentry/icmp_rcv")
int BPF_PROG(tg_icmp_rcv, struct sk_buff *skb)
{
	icmp_rcv(ctx, skb);

	return 0;
}

// Handles received ICMPv6 packets. We assume they are all linear and
// therefore can be read successfully with probe_read.
SEC("fentry/icmpv6_rcv")
int BPF_PROG(tg_icmpv6_rcv, struct sk_buff *skb)
{
	icmp_rcv(ctx, skb);

	return 0;
}
