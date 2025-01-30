// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#include "parsers/dns/parser.h"

__attribute__((section("cgroup_skb/egress"), used)) int
test_dns_parser(struct __sk_buff *skb)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct dnshdr *dns;
	int8_t error;
	uint32_t error_idx, *counter;

	// Verify if the frame contains an IP packet.
	if (skb->protocol != bpf_htons(ETH_P_IP)) {
		// skip non IP packets.
		error = -1;
		goto test_give_up;
	}

	// Parse IP header.
	ip = (struct iphdr *)(long)skb->data;
	// Verify that there's something next to the IP header.
	if (ip + 1 > (void *)(long)skb->data_end) {
		error = -2;
		goto test_give_up;
	}

	// Verify if protocol is UDP.
	if (ip->protocol != IPPROTO_UDP) {
		// Skip non-UDP packets.
		error = -3;
		goto test_give_up;
	}

	// Parse UDP header.
	udp = (void *)ip + (ip->ihl * sizeof(u32)); // ihl is in 32 bits words.
	// Verify that there's something next to the UDP header.
	if (udp + 1 > (void *)(long)skb->data_end) {
		error = -4;
		goto test_give_up;
	}

	// Verify if that source port (answer) is DNS.
	if (udp->source != bpf_htons(DNS_PORT)) {
		// Skip non-DNS answers packets.
		error = -5;
		goto test_give_up;
	}

	// Parse the DNS header.
	dns = (void *)udp + sizeof(struct udphdr);

	int parser_ret = parse_dns(skb, (void *)dns - (void *)ip);
	if (parser_ret < 0) {
		DEBUG("parser failed with: %d", parser_ret);
	}
	return SK_PASS;

test_give_up:
	if (error <= 0) {
		error_idx = -error;
		counter = map_lookup_elem(&tg_dns_error_map, &error_idx);
		if (counter)
			(*counter)++; // It's a per cpu array
	}
	return SK_PASS;
}
