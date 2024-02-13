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
#include "bpf_timestamp.h"
#include "../bpf_network_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("classifier/egress_timestamp"), used)) int
tg_egress_timestamp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;

	if (data + sizeof(*eth) > data_end) {
		return TC_ACT_PIPE;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_IP_P) {
		return TC_ACT_PIPE;
	}

	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		return TC_ACT_PIPE;
	}

	iph = data + sizeof(*eth);
	switch (iph->version) {
	case 4:
		if (egress_timestamp4(skb, data, data_end, eth, iph)) {
			return TC_ACT_PIPE;
		} else {
			return TC_ACT_SHOT;
		}
		break;
	case 6:
		if (egress_timestamp6(skb, data, data_end, eth)) {
			return TC_ACT_PIPE;
		} else {
			return TC_ACT_SHOT;
		}
		break;
	default:
		emit_ip_error_event(skb, 0, 0, false, iph->version, 2, 0, IP_ERROR_INET_NO_VERSION);
		return TC_ACT_PIPE;
	}
}
