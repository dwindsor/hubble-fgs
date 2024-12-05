// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#include "../parsers/dns/dns_parser.h"

__attribute__((section("cgroup_skb/egress"), used)) int
test_dns_parser(struct __sk_buff *skb)
{
	return parse_dns(skb);
}
