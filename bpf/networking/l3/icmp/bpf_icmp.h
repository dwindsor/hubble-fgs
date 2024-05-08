// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_ICMP_H_
#define __BPF_ICMP_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_cookie.h"
#include "../bpf_network_helpers.h"
#include "../lib/address_family.h"
#include "../lib/config.h"
#include "bpf_icmp_cookie.h"
#include "bpf_tracing.h"

#define ICMP_HDR_LEN	  4
#define ICMP_HDR_DATA_OFF 4

// Taken from include/uapi/linux/icmp.h
#define ICMP_ECHOREPLY	    0 /* Echo Reply			*/
#define ICMP_DEST_UNREACH   3 /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH  4 /* Source Quench		*/
#define ICMP_REDIRECT	    5 /* Redirect (change route)	*/
#define ICMP_ECHO	    8 /* Echo Request			*/
#define ICMP_TIME_EXCEEDED  11 /* Time Exceeded		*/
#define ICMP_PARAMETERPROB  12 /* Parameter Problem		*/
#define ICMP_TIMESTAMP	    13 /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST   15 /* Information Request		*/
#define ICMP_INFO_REPLY	    16 /* Information Reply		*/
#define ICMP_ADDRESS	    17 /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY   18 /* Address Mask Reply		*/

// Taken from include/uapi/linux/icmpv6.h
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG   2
#define ICMPV6_TIME_EXCEED  3
#define ICMPV6_PARAMPROB    4
#define ICMPV6_ERRMSG_MAX   127
#define ICMPV6_INFOMSG_MASK 0x80
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY   129

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_icmp_event);
	__uint(max_entries, 1);
} icmp_event_heap SEC(".maps");

struct icmp_config {
	u8 v6_info;
	u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct icmp_config);
	__uint(max_entries, 1);
} tg_icmp_cfg_map SEC(".maps");

#define IPSKB_L3SLAVE  (1 << 7) // As defined in kernel
#define IP6SKB_L3SLAVE 64 // As defined in kernel

static inline __attribute__((always_inline)) int
inet_sdif(struct sk_buff *skb)
{
	struct netns_ipv4___with_l3mdev *ipv4;
	struct inet_skb_parm *ipcb;
	struct net *net = 0;
	__u16 flags;
	int iif;

	ipv4 = (struct netns_ipv4___with_l3mdev *)&net->ipv4;
	if (!bpf_core_field_exists(ipv4->sysctl_raw_l3mdev_accept))
		return 0;

	ipcb = (struct inet_skb_parm *)_(&(skb->cb));
	probe_read_kernel(&flags, sizeof(flags), _(&(ipcb->flags)));
	if (flags & IPSKB_L3SLAVE) {
		probe_read_kernel(&iif, sizeof(iif), _(&(ipcb->iif)));
		return iif;
	}
	return 0;
}

static inline __attribute__((always_inline)) int
inet6_sdif(struct sk_buff *skb)
{
	struct netns_ipv4___with_l3mdev *ipv4; // Only used to check for config option
	struct inet6_skb_parm *ipcb;
	struct net *net = 0;
	__u16 flags;
	int iif;

	ipv4 = (struct netns_ipv4___with_l3mdev *)&net->ipv4;
	if (!bpf_core_field_exists(ipv4->sysctl_raw_l3mdev_accept))
		return 0;

	ipcb = (struct inet6_skb_parm *)_(&(skb->cb));
	probe_read_kernel(&flags, sizeof(flags), _(&(ipcb->flags)));
	if (flags & IP6SKB_L3SLAVE) {
		probe_read_kernel(&iif, sizeof(iif), _(&(ipcb->iif)));
		return iif;
	}
	return 0;
}

static inline __attribute__((always_inline)) void
send_icmp_event(void *ctx, struct msg_icmp_event *val, u64 *cookie, struct sk_buff *skb, u8 protocol, u16 sport)
{
	struct socketmap_value *process = 0;
	struct socket_tuple_key *key;
	struct net_device *dev;
	u64 *new_cookie;
	int dif, sdif;

	if (*cookie) {
		__u64 c = *cookie;
		process = lookup_socketmap(&c);
	}
	if (!process && icmp_tracking_enabled() && skb && protocol && sport) {
		key = make_tuple_key_from_skb(skb, val, protocol, sport);
		if (key) {
			probe_read_kernel(&dev, sizeof(dev), _(&(skb->dev)));
			probe_read_kernel(&dif, sizeof(dif), _(&(dev->ifindex))); // might need additional checks for IPv6
			if (val->tuple.ipv6)
				sdif = inet_sdif(skb);
			else
				sdif = inet6_sdif(skb);
			new_cookie = lookup_socket_tuple_map(key, dif, sdif);
			if (new_cookie && *new_cookie)
				process = lookup_socketmap(new_cookie);
		}
	}
	if (process) {
		val->key.pid = process->key.pid;
		val->key.ktime = process->key.ktime;
	} else {
		val->key.pid = 0;
		val->key.ktime = 1;
	}
	val->common.ktime = ktime_get_ns();
	val->common.size = sizeof(struct msg_icmp_event);
	val->socket_cookie = *cookie;
	perf_event_output_metric(ctx, ISO_MSG_OP_ICMP, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				 sizeof(struct msg_icmp_event));
}

#ifdef SKB_LOAD_BYTES
int icmp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	u8 icmp_data[ICMP_HDR_LEN * 2];
	struct msg_icmp_event *val;
	struct iphdr rep_ip4;
	struct tcphdr tcp;
	int zero = 0;

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return SK_PASS;

	if (unlikely(!ip))
		return SK_PASS;

	if (unlikely(!cookie))
		return SK_PASS;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	if (skb_load_bytes(skb, ip->ihl * sizeof(u32), icmp_data, sizeof(icmp_data)) < 0) {
		// TBD: JF Fix the compiler please.
		u64 c = *cookie; // compiler + verifier oddity to coerce this into a correct verifier type
		emit_ip_error_event(skb, ip, &c, false, ip->version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
		return SK_PASS;
	}

	val->icmp_type = icmp_data[0];
	val->icmp_code = icmp_data[1];
	val->common.op = ISO_MSG_OP_ICMP;
	val->icmp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
	*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

	if (send) {
		val->tuple.saddr[0] = ip->saddr;
		val->tuple.daddr[0] = ip->daddr;
	} else {
		val->tuple.saddr[0] = ip->daddr;
		val->tuple.daddr[0] = ip->saddr;
	}
	val->tuple.saddr[1] = 0;
	val->tuple.daddr[1] = 0;
	val->tuple.ipv6 = 0;
	val->tuple.proto = IPPROTO_ICMP;

	if (skb_load_bytes(skb, (ip->ihl * sizeof(u32)) + sizeof(icmp_data), &rep_ip4, sizeof(rep_ip4)) == 0) {
		val->icmp_ip_proto = rep_ip4.protocol;
		switch (val->icmp_type) {
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			val->icmp_ip_ttl = rep_ip4.ttl;

			switch (val->icmp_ip_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP: // Note ports are in the same location in TCP and UDP headers
				if (skb_load_bytes(skb, (ip->ihl * sizeof(u32)) + sizeof(icmp_data) + sizeof(rep_ip4), &tcp, sizeof(tcp)) == 0)
					val->icmp_ip_port = bpf_ntohs(tcp.dest);
				break;
			}
			break;
		}
	}
	if (val->icmp_type == ICMP_PARAMETERPROB)
		val->icmp_ip_pointer = val->icmp_data[0];
	if (val->icmp_type == ICMP_REDIRECT)
		val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);

	send_icmp_event(skb, val, cookie, 0, 0, 0);
	return SK_PASS;
}
#else
int icmp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct msg_icmp_event *val;
	struct tcphdr *tcp;
	u8 *icmp_data;
	int zero = 0;

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return SK_PASS;

	if (unlikely(!ip))
		return SK_PASS;

	if (unlikely(!cookie))
		return SK_PASS;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	if (data + (ip->ihl * sizeof(u32)) + ICMP_HDR_LEN + sizeof(u32) > data_end) {
		// TBD: JF Fix the compiler please.
		u64 c = *cookie; // compiler + verifier oddity to coerce this into a correct verifier type
		emit_ip_error_event(skb, ip, &c, false, ip->version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
		return SK_PASS;
	}

	icmp_data = (u8 *)data + (ip->ihl * sizeof(u32));
	val->icmp_type = icmp_data[0];
	val->icmp_code = icmp_data[1];
	val->common.op = ISO_MSG_OP_ICMP;
	val->icmp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
	*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);
	if (send) {
		val->tuple.saddr[0] = ip->saddr;
		val->tuple.daddr[0] = ip->daddr;
	} else {
		val->tuple.saddr[0] = ip->daddr;
		val->tuple.daddr[0] = ip->saddr;
	}
	val->tuple.saddr[1] = 0;
	val->tuple.daddr[1] = 0;
	val->tuple.ipv6 = 0;
	val->tuple.proto = IPPROTO_ICMP;

	if (icmp_data + ICMP_HDR_LEN + sizeof(u32) + sizeof(struct iphdr) <= data_end) {
		struct iphdr *rep_ip4;
		u8 *rep_ptr;

		rep_ptr = icmp_data + ICMP_HDR_LEN + sizeof(u32);
		rep_ip4 = (struct iphdr *)rep_ptr;
		val->icmp_ip_proto = rep_ip4->protocol;

		switch (val->icmp_type) {
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			val->icmp_ip_ttl = rep_ip4->ttl;

			switch (val->icmp_ip_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP: // Note ports are in the same location in TCP and UDP headers
				tcp = (struct tcphdr *)(rep_ptr + (rep_ip4->ihl * sizeof(u32)));
				if (tcp + sizeof(struct tcphdr) > data_end)
					break;
				val->icmp_ip_port = tcp->dest;
				break;
			}
			break;
		}
	}
	if (val->icmp_type == ICMP_PARAMETERPROB)
		val->icmp_ip_pointer = val->icmp_data[0];
	if (val->icmp_type == ICMP_REDIRECT)
		val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);

	send_icmp_event(skb, val, cookie, 0, 0, 0);
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES

#ifdef SKB_LOAD_BYTES
int icmp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 off, int send)
{
	u8 icmp_data[ICMP_HDR_LEN * 2];
	struct msg_icmp_event *val;
	struct icmp_config *cfg;
	struct ipv6hdr rep_ip6;
	struct tcphdr tcp;
	int zero = 0;

	if (unlikely(!ip6))
		return SK_PASS;

	if (unlikely(!cookie))
		return SK_PASS;

	if (!off) {
		emit_ip_error_event(skb, ip6, cookie, true, 6, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
		return SK_PASS;
	}

	if (skb_load_bytes(skb, off, icmp_data, sizeof(icmp_data)) < 0) {
		emit_ip_error_event(skb, ip6, cookie, false, 6, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
		return SK_PASS;
	}

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return SK_PASS;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	val->icmp_type = icmp_data[0];
	val->icmp_code = icmp_data[1];

	cfg = map_lookup_elem(&tg_icmp_cfg_map, &zero);
	if (cfg && !cfg->v6_info && val->icmp_type > ICMPV6_ECHO_REPLY)
		return SK_PASS;

	val->common.op = ISO_MSG_OP_ICMP;
	val->icmp_len = skb->len - off - ICMP_HDR_LEN - sizeof(u32); // total len - payload offset - ICMP header
	*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

	if (send) {
		copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6->saddr);
		copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6->daddr);
	} else {
		copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6->daddr);
		copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6->saddr);
	}
	val->tuple.ipv6 = 1;
	val->tuple.proto = IPPROTO_ICMP6;

	switch (val->icmp_type) {
	case ICMPV6_DEST_UNREACH:
	case ICMPV6_PKT_TOOBIG:
	case ICMPV6_TIME_EXCEED:
	case ICMPV6_PARAMPROB:
		if (skb_load_bytes(skb, off + sizeof(icmp_data), &rep_ip6, sizeof(rep_ip6)) == 0) {
			val->icmp_ip_ttl = rep_ip6.hop_limit;

			switch (rep_ip6.nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				if (skb_load_bytes(skb, off + sizeof(icmp_data) + sizeof(rep_ip6), &tcp, sizeof(tcp)) == 0)
					val->icmp_ip_port = bpf_ntohs(tcp.dest);
				val->icmp_ip_proto = IPPROTO_TCP;
				break;
			}
			break;
		}
	}
	if (val->icmp_type == ICMPV6_PARAMPROB)
		val->icmp_ip_pointer = *(u32 *)val->icmp_data;

	send_icmp_event(skb, val, cookie, 0, 0, 0);
	return SK_PASS;
}
#else
int icmp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 off, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct msg_icmp_event *val;
	struct icmp_config *cfg;
	struct ipv6hdr *rep_ip6;
	struct tcphdr *tcp;
	u8 *icmp_data;
	int zero = 0;
	u8 *rep_ptr;

	if (!skb)
		return SK_PASS;

	if (!ip6)
		return SK_PASS;

	if (!cookie)
		return SK_PASS;

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return SK_PASS;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	if (off > 0x7fff)
		return SK_PASS;

	/* asm to enforce the boundary on the payload otherwise we hit
	 * a verifier error trying to access past the end of the 65k payload.
	 * We artificially limit to 0x7fffB offset into payload.
	 */
	asm volatile("%[off] &= 0x7fff;\n" :[off] "+r"(off):);
	if (data + off + ICMP_HDR_LEN + sizeof(u32) > data_end) {
		// TBD: JF Fix the compiler please.
		u64 c = *cookie; // compiler + verifier oddity to coerce this into a correct verifier type
		emit_ip_error_event(skb, ip6, &c, false, 6, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
		return SK_PASS;
	}
	icmp_data = (u8 *)data + off;
	val->icmp_type = icmp_data[0];
	val->icmp_code = icmp_data[1];

	cfg = map_lookup_elem(&tg_icmp_cfg_map, &zero);
	if (cfg && !cfg->v6_info && val->icmp_type > ICMPV6_ECHO_REPLY)
		return SK_PASS;

	val->common.op = ISO_MSG_OP_ICMP;
	val->icmp_len = (data_end - data) - off - ICMP_HDR_LEN - sizeof(u32); // total len - payload offset - ICMP header
	*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

	if (send) {
		copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6->saddr);
		copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6->daddr);
	} else {
		copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6->daddr);
		copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6->saddr);
	}
	val->tuple.ipv6 = 1;
	val->tuple.proto = IPPROTO_ICMP6;

	if (icmp_data + ICMP_HDR_LEN + sizeof(u32) + sizeof(struct ipv6hdr) <= data_end) {
		switch (val->icmp_type) {
		case ICMPV6_DEST_UNREACH:
		case ICMPV6_PKT_TOOBIG:
		case ICMPV6_TIME_EXCEED:
		case ICMPV6_PARAMPROB:
			rep_ptr = icmp_data + ICMP_HDR_LEN + sizeof(u32);
			rep_ip6 = (struct ipv6hdr *)rep_ptr;
			val->icmp_ip_ttl = rep_ip6->hop_limit;
			// For the reported datagram header, we're taking the short cut of assuming there
			// are no IPv6 header extensions. This seems bold and risky, but actually, it just
			// means that we will not report the protocol or port if the reported datagram
			// includes IPv6 header extensions. If this becomes a problem, we can revisit it,
			// but the complexity arising from parsing IPv6 header extensions within the
			// reported datagram header was just too much for clang+verifier combined, hence
			// this short cut for now.
			switch (rep_ip6->nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				if (rep_ptr + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end)
					break;
				tcp = (struct tcphdr *)(rep_ptr + sizeof(struct ipv6hdr));
				val->icmp_ip_port = bpf_ntohs(tcp->dest);
				val->icmp_ip_proto = IPPROTO_TCP;
				break;
			}
		}
	}
	if (val->icmp_type == ICMPV6_PARAMPROB)
		val->icmp_ip_pointer = *(u32 *)val->icmp_data;

	send_icmp_event(skb, val, cookie, 0, 0, 0);
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES

#endif //__BPF_ICMP_H_
