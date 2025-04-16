// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#define TRACK_ICMP_FROM_SKB
#define NO_CGROUP_PROBE_READ

#include "vmlinux.h"
#include "icmp/bpf_icmp.h"
#include "bpf_dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_cgroup_ingress(struct __sk_buff *skb)
{
	tg_cgroup_dispatcher(skb, 0);
	return SK_PASS;
}

__attribute__((section("cgroup_skb/egress"), used)) int
tg_cgroup_egress(struct __sk_buff *skb)
{
	tg_cgroup_dispatcher(skb, 1);
	return SK_PASS;
}
