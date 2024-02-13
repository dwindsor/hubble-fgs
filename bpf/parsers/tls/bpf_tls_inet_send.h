// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TLS_INET_SEND_H_
#define __BPF_TLS_INET_SEND_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../networking/bpf_cookie.h"
#include "../networking/bpf_network_helpers.h"
#include "tls_map.h"
#include "tls_parser.h"
#include "egress.h"
#include "ingress.h"

struct tls_packet_details {
	union {
		struct iphdr ip4;
		struct ipv6hdr ip6;
	} ip;
	struct tcphdr tcp;
	u16 tcp_off;
	int payload_off;
	void *skb_head;
	u8 version;
	u8 protocol;
	u16 network_header_off;
	bool ipv6;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct tls_packet_details);
	__uint(max_entries, 1);
} tls_header_heap SEC(".maps");

static inline __attribute__((always_inline)) u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline)) struct tls_packet_details *tls_inet_send_handler(struct __sk_buff *skb, u64 send)
{
	struct tls_packet_details *packet = 0;
	struct sock_key filter_key = { 0 };
	unsigned long int err = 0;
	int zero = 0;
	u64 *cookie;
	int result;
	u8 proto;

	cookie = map_lookup_elem(&tg_tls_cookie_heap, &zero);
	if (!cookie)
		return 0;
	write_cookie(cookie, (u64)skb->sk);
	if (!*cookie)
		return 0;

	packet = map_lookup_elem(&tls_header_heap, &zero);
	if (!packet)
		return 0;

	if (skb_load_bytes(skb, 0, &packet->ip, sizeof(struct iphdr)) < 0)
		return 0;

	switch (packet->ip.ip4.version) {
	case 4:
		if (packet->ip.ip4.protocol != IPPROTO_TCP)
			return 0;
		packet->ipv6 = false;
		packet->tcp_off = ip_payload_off(&packet->ip.ip4);
		break;
	case 6:
		if (skb_load_bytes(skb, 0, &packet->ip,
				   sizeof(struct ipv6hdr)) < 0)
			return 0;
		packet->ipv6 = true;
		proto = get_ip6_proto(&packet->tcp_off, &packet->ip.ip6, 0, skb,
				      0, true, false, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &packet->ip.ip6, cookie, true,
					    packet->ip.ip4.version, send + 1, 0, err);
			return 0;
		} else if (proto != IPPROTO_TCP) {
			return 0;
		}
		if (!packet->tcp_off)
			return 0;
		break;
	default:
		return 0;
	}
	if (skb_load_bytes(skb, packet->tcp_off, &packet->tcp,
			   sizeof(struct tcphdr)) < 0)
		return 0;

	filter_key.sport = packet->tcp.source;
	filter_key.dport = packet->tcp.dest;
	result = tls_filter(&filter_key);
	if (result == PROTO_SKIP)
		return 0;

	packet->payload_off = (packet->tcp.doff * 4) + packet->tcp_off;
	return packet;
}

#endif //__BPF_TLS_INET_SEND_H_
