// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

#include "vmlinux.h"

#include "bpf_tracing.h" // bpf_printk

#include "bpf_task.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

__attribute__((section("cgroup_skb/egress"), used)) int
test_dns_parser()
{
	return 1;
}

