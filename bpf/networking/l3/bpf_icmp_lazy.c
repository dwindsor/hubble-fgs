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
#include "bpf_icmp.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_icmp_recv_lazy(struct __sk_buff *skb)
{
	icmp_handler_lazy(skb, false);
	return SK_PASS;
}

__attribute__((section("cgroup_skb/egress"), used)) int
tg_icmp_send_lazy(struct __sk_buff *skb)
{
	icmp_handler_lazy(skb, true);
	return SK_PASS;
}
