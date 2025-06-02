// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#include "parsers/dns/parser.h"

__attribute__((section("cgroup_skb/egress"), used)) int
test_dns_parser(struct __sk_buff *skb)
{
	void *ip;
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct dnshdr *dns;
	int8_t error;
	uint32_t error_idx, *counter;
	int send;

	switch (bpf_ntohs(skb->protocol)) {
	case ETH_P_IP:
		ip4 = (struct iphdr *)(long)skb->data;
		if (ip4 + 1 > (void *)(long)skb->data_end) {
			error = -2;
			goto test_give_up;
		}

		if (ip4->protocol != IPPROTO_UDP) {
			// Skip non-UDP packets.
			error = -3;
			goto test_give_up;
		}

		udp = (void *)ip4 + (ip4->ihl * sizeof(u32)); // ihl is in 32 bits words.
		if (udp + 1 > (void *)(long)skb->data_end) {
			error = -4;
			goto test_give_up;
		}
		ip = ip4;
		break;
	case ETH_P_IPV6:
		ip6 = (struct ipv6hdr *)(long)skb->data;
		if (ip6 + 1 > (void *)(long)skb->data_end) {
			error = -2;
			goto test_give_up;
		}

		// TODO: there could extension headers, so far that's okay
		// because this is just the testing framework and I don't have
		// test cases for this
		if (ip6->nexthdr != IPPROTO_UDP) {
			// Skip non-UDP packets.
			error = -3;
			goto test_give_up;
		}

		udp = (void *)ip6 + sizeof(struct ipv6hdr); // ihl is in 32 bits words.
		if (udp + 1 > (void *)(long)skb->data_end) {
			error = -4;
			goto test_give_up;
		}
		ip = ip6;
		break;
	default:
		// skip non IP packets.
		error = -1;
		goto test_give_up;
	}

	// Verify if that source (answer) or dest (query) port is DNS.
	if (udp->source != bpf_htons(DNS_PORT) && udp->dest != bpf_htons(DNS_PORT)) {
		// Skip non-DNS packets.
		error = -5;
		goto test_give_up;
	}

	// Parse the DNS header.
	dns = (void *)udp + sizeof(struct udphdr);

	// Need to artifially alternate between egress and ingress
	send = udp->source == bpf_htons(DNS_PORT);

	int parser_ret = parse_dns(skb, (void *)dns - (void *)ip, send);
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
