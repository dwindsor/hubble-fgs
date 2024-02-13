// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_ICMP_RCV_H_
#define __BPF_ICMP_RCV_H_

#include "vmlinux.h"
#include "bpf_icmp.h"
#include "../udp/bpf_udp_event.h"

static inline __attribute__((always_inline)) int
icmp_rcv(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	u8 icmp_data[ICMP_HDR_LEN];
	struct msg_icmp_event *val;
	u16 transport_header_off;
	struct icmp_config *cfg;
	struct ipv6hdr *rep_ip6;
	u16 network_header_off;
	struct iphdr *rep_ip4;
	struct tcphdr *tcp;
	struct ipv6hdr ip6;
	void *skb_head = 0;
	unsigned long err;
	struct iphdr ip4;
	struct ihlver iv;
	u16 payload_off;
	u16 sport = 0;
	u16 protocol;
	int zero = 0;
	u64 cookie;
	u8 version;
	u32 len;

	probe_read(&cookie, sizeof(cookie), _(&(skb->sk)));

	version = get_ip_version(&network_header_off, &skb_head, skb);

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return 0;

	val->tuple.send = 0;

	switch (version) {
	case 4:
		if (!get_ip4_header(&ip4, network_header_off, skb_head)) {
			emit_ip_error_event(ctx, 0, &cookie, false,
					    version, 1, 0, IP_ERROR_INET_READ_IP);
			return 0;
		}
		if (ip4.protocol != IPPROTO_ICMP)
			return 0;

		if (probe_read(&transport_header_off, sizeof(transport_header_off),
			       _(&(skb->transport_header))) < 0) {
			emit_ip_error_event(ctx, &ip4, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}
		if (probe_read(icmp_data, sizeof(icmp_data), skb_head + transport_header_off) < 0) {
			emit_ip_error_event(ctx, &ip4, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}

		val->icmp_type = icmp_data[0];
		// Don't handle Echo Reply here as it will be handled by cgroup_skb ingress.
		if (val->icmp_type == ICMP_ECHOREPLY)
			return 0;
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip4.tot_len) - (ip4.ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
		probe_read(val->icmp_data, sizeof(val->icmp_data), skb_head + transport_header_off + ICMP_HDR_LEN);

		val->tuple.saddr[0] = ip4.daddr;
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[0] = ip4.saddr;
		val->tuple.daddr[1] = 0;
		val->tuple.ipv6 = 0;
		val->tuple.proto = IPPROTO_ICMP;
		val->icmp_ip_port = 0;
		val->icmp_ip_ttl = 0;
		val->icmp_ip_pointer = 0;
		val->icmp_gateway[0] = 0;
		val->icmp_gateway[1] = 0;

		rep_ip4 = (struct iphdr *)(skb_head + transport_header_off + ICMP_HDR_LEN + sizeof(u32));
		probe_read(&val->icmp_ip_proto, sizeof(val->icmp_ip_proto), &rep_ip4->protocol);

		switch (val->icmp_type) {
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			probe_read(&val->icmp_ip_ttl, sizeof(val->icmp_ip_ttl), &rep_ip4->ttl);
			probe_read(&iv, sizeof(iv), rep_ip4);
			switch (val->icmp_ip_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				tcp = (struct tcphdr *)((char *)rep_ip4 + (iv.ihl * sizeof(u32)));
				probe_read(&val->icmp_ip_port, sizeof(val->icmp_ip_port), &tcp->dest);
				val->icmp_ip_port = bpf_ntohs(val->icmp_ip_port);
				probe_read(&sport, sizeof(sport), &tcp->source);
				sport = bpf_ntohs(sport);
				break;
			default:
				val->icmp_ip_proto = 0;
			}
			break;
		}

		if (val->icmp_type == ICMP_PARAMETERPROB)
			val->icmp_ip_pointer = val->icmp_data[0];
		if (val->icmp_type == ICMP_REDIRECT) {
			val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);
		}

		send_icmp_event(ctx, val, &cookie, skb, val->icmp_ip_proto, sport);
		break;
	case 6:
		if (!get_ip6_header(&ip6, network_header_off, skb_head)) {
			emit_ip_error_event(ctx, 0, &cookie, false,
					    version, 1, 0, IP_ERROR_INET_READ_IP);
			return 0;
		}
		protocol = get_ip6_proto(&payload_off, &ip6, network_header_off, skb_head, 0, true, true, &err);
		if (protocol == IP_HEADER_ERROR) {
			emit_ip_error_event(ctx, &ip6, &cookie, true, ip6.version, 1, 0, IP_ERROR_INET_READ_IP);
			return 0;
		}
		if (protocol != IPPROTO_ICMP6)
			return 0;

		if (probe_read(&transport_header_off, sizeof(transport_header_off),
			       _(&(skb->transport_header))) < 0) {
			emit_ip_error_event(ctx, &ip6, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}
		if (probe_read(icmp_data, sizeof(icmp_data), skb_head + transport_header_off) < 0) {
			emit_ip_error_event(ctx, &ip6, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}

		val->icmp_type = icmp_data[0];
		// Don't handle Echo Reply here as it will be handled by cgroup_skb ingress.
		if (val->icmp_type == ICMPV6_ECHO_REPLY)
			return 0;
		val->icmp_code = icmp_data[1];

		cfg = map_lookup_elem(&tg_icmp_cfg_map, &zero);
		if (cfg && !cfg->v6_info && val->icmp_type > ICMPV6_ECHO_REPLY)
			return 0;

		val->common.op = ISO_MSG_OP_ICMP;
		// ICMP len = skb->len - ICMP header
		probe_read(&len, sizeof(len), _(&(skb->len)));
		val->icmp_len = len - ICMP_HDR_LEN - sizeof(u32);
		probe_read(val->icmp_data, sizeof(val->icmp_data), skb_head + transport_header_off + ICMP_HDR_LEN);

		copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6.daddr);
		copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6.saddr);
		val->tuple.ipv6 = 1;
		val->tuple.proto = IPPROTO_ICMP6;
		val->icmp_ip_port = 0;
		val->icmp_ip_ttl = 0;
		val->icmp_ip_pointer = 0;
		val->icmp_gateway[0] = 0;
		val->icmp_gateway[1] = 0;

		switch (val->icmp_type) {
		case ICMPV6_DEST_UNREACH:
		case ICMPV6_PKT_TOOBIG:
		case ICMPV6_TIME_EXCEED:
		case ICMPV6_PARAMPROB:
			// For the reported datagram header, we're taking the short cut of assuming there
			// are no IPv6 header extensions. This seems bold and risky, but actually, it just
			// means that we will not report the protocol or port if the reported datagram
			// includes IPv6 header extensions. If this becomes a problem, we can revisit it,
			// but the complexity arising from parsing IPv6 header extensions within the
			// reported datagram header was just too much for clang+verifier combined, hence
			// this short cut for now.
			rep_ip6 = (struct ipv6hdr *)(skb_head + transport_header_off + ICMP_HDR_LEN + sizeof(u32));
			probe_read(&val->icmp_ip_ttl, sizeof(val->icmp_ip_ttl), &rep_ip6->hop_limit);
			probe_read(&val->icmp_ip_proto, sizeof(val->icmp_ip_proto), &rep_ip6->nexthdr);
			switch (val->icmp_ip_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				tcp = (struct tcphdr *)((char *)rep_ip6 + sizeof(struct ipv6hdr));
				probe_read(&val->icmp_ip_port, sizeof(val->icmp_ip_port), &tcp->dest);
				val->icmp_ip_port = bpf_ntohs(val->icmp_ip_port);
				probe_read(&sport, sizeof(sport), &tcp->source);
				sport = bpf_ntohs(sport);
				break;
			default:
				val->icmp_ip_proto = 0;
			}
			break;
		}

		if (val->icmp_type == ICMPV6_PARAMPROB)
			val->icmp_ip_pointer = *(u32 *)val->icmp_data;

		send_icmp_event(ctx, val, &cookie, skb, val->icmp_ip_proto, sport);
		break;
	default:
		emit_ip_error_event(ctx, 0, &cookie, false, version, 1, 0, IP_ERROR_INET_NO_VERSION);
		return 0;
	}
	return 0;
}

#endif