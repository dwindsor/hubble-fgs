// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_NETWORK_HELPERS_H__
#define __BPF_NETWORK_HELPERS_H__

#include "lib/bpf_helpers.h"
#include "lib/iso_msg_types.h"
#include "lib/networkmsg.h"
#include "bpf_cookie.h"
#include "l3/tcp/bpf_tcp_info.h"

#define IP_HEADER_ERROR			     0
#define IP_ERROR_NO_HEAP		     1
#define IP_ERROR_IPV6_READ_PROBE	     2
#define IP_ERROR_IPV6_READ_SKB_LOAD	     3
#define IP_ERROR_IPV6_READ_SKB_DIRECT	     4
#define IP_ERROR_IPV6_UNKNOWN_EXT	     5
#define IP_ERROR_IPV6_TOO_MANY_EXT	     6
#define IP_ERROR_INET_NO_COOKIE		     7
#define IP_ERROR_INET_READ_VER		     8
#define IP_ERROR_INET_READ_IP		     9
#define IP_ERROR_INET_READ_UDP		     10
#define IP_ERROR_INET_NO_PAYLOAD_OFFSET	     11
#define IP_ERROR_INET_NO_VERSION	     12
#define IP_ERROR_INET_WATERMARK_NO_PROCESS   13
#define IP_ERROR_INET_WATERMARK_NO_PID	     14
#define IP_ERROR_INET_READ_PAYLOAD	     15
#define IP_ERROR_UDP_SEND_NO_SOCK_INFO	     16
#define IP_ERROR_UDP_SEND_NO_COOKIE	     17
#define IP_ERROR_UDP_RECV_NO_COOKIE	     18
#define IP_ERROR_UDP_RECV_READ_IP	     19
#define IP_ERROR_UDP_RECV_READ_UDP	     20
#define IP_ERROR_UDP_RECV_NO_VERSION	     21
#define IP_ERROR_SOCK_CREATE_NO_COOKIE	     22
#define IP_ERROR_SOCK_RELEASE_NO_COOKIE	     23
#define IP_ERROR_INET_READ_IP_OPTION	     24
#define IP_ERROR_UDP_RETPROBE_ADD	     25
#define IP_ERROR_UDP_RETPROBE_DEL	     26
#define IP_ERROR_SOCK_RELEASE_NO_SOCK	     27
#define IP_ERROR_UDP_SEND_MISSING_PROCESS    28
#define IP_ERROR_UDP_RECV_MISSING_PROCESS    29
#define IP_ERROR_UPDATE_SOCKETMAP_NO_PROCESS 30
#define IP_ERROR_SOCKET_DISCOVERY_NO_PROCESS 31
#define IP_ERROR_SOCKET_DISCOVERY_READ_ERROR 32
#define IP_ERROR_SOCK_CREATE_NO_PROCESS	     33
#define IP_ERROR_SOCKET_DISCOVERY_NO_SK	     34
#define IP_ERROR_SOCK_CREATE_PID_0	     35
#define IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS  36
#define IP_ERROR_UDP_SEQ_READ_PAYLOAD_DATA   37

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} ip_error_event_heap SEC(".maps");

static inline __attribute__((always_inline)) int cgrp_tcp_socketmap_stats(struct sock *sk, struct tcpsocketmap_value *v)
{
	struct tcp_sock *tcp;
	struct sock *skp;

	if (!sk)
		return SK_PASS;
	if (!v)
		return SK_PASS;

	tcp = skc_to_tcp_sock(sk);
	if (!tcp)
		return SK_PASS;
	skp = (struct sock *)tcp;

	v->last_time = ktime_get_ns();

	if (bpf_core_field_exists(tcp->bytes_sent))
		probe_read_kernel(&v->sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	if (bpf_core_field_exists(tcp->bytes_sent))
		probe_read_kernel(&v->sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	if (bpf_core_field_exists(tcp->segs_out))
		probe_read_kernel(&v->segs_out, sizeof(__u32), _(&(tcp->segs_out)));
	if (bpf_core_field_exists(tcp->bytes_retrans))
		probe_read_kernel(&v->retransbytes, sizeof(__u64), _(&(tcp->bytes_retrans)));

	if (bpf_core_field_exists(skp->sk_drops))
		probe_read_kernel(&v->sk_drops, sizeof(__u32), _(&(skp->sk_drops)));

	/* These statistics are known to exist back to 4.12 kernels.
	 */
	probe_read_kernel(&v->received, sizeof(__u64), _(&(tcp->bytes_received)));
	probe_read_kernel(&v->segs_in, sizeof(__u32), _(&(tcp->segs_in)));
	probe_read_kernel(&v->srtt, sizeof(__u32), _(&(tcp->srtt_us)));
	v->srtt = v->srtt / 8; // SRTT is reported <<3 in us.
	probe_read_kernel(&v->retranssegs, sizeof(__u32), _(&(tcp->total_retrans)));

	return SK_PASS;
}

static inline __attribute__((always_inline)) void
tcp_socketmap_stats(struct sock *sk, struct tcpsocketmap_value *v)
{
	struct tcp_sock *tcp = (struct tcp_sock *)sk;

	/* Set the time the stats were obtained to allow checking of event ordering */
	v->last_time = ktime_get_ns();

	/* Older kernels will not have these statistics. To get a full set of
	 * stats run 4.19 or higher.
	 */
	if (bpf_core_field_exists(tcp->bytes_sent))
		probe_read_kernel(&v->sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	if (bpf_core_field_exists(tcp->segs_out))
		probe_read_kernel(&v->segs_out, sizeof(__u32), _(&(tcp->segs_out)));
	if (bpf_core_field_exists(tcp->bytes_retrans))
		probe_read_kernel(&v->retransbytes, sizeof(__u64), _(&(tcp->bytes_retrans)));
	if (bpf_core_field_exists(sk->sk_drops))
		probe_read_kernel(&v->sk_drops, sizeof(__u32), _(&(sk->sk_drops)));

	/* These statistics are known to exist back to 4.12 kernels.
	 */
	probe_read_kernel(&v->received, sizeof(__u64), _(&(tcp->bytes_received)));
	probe_read_kernel(&v->segs_in, sizeof(__u32), _(&(tcp->segs_in)));
	probe_read_kernel(&v->srtt, sizeof(__u32), _(&(tcp->srtt_us)));
	v->srtt = v->srtt / 8; // SRTT is reported <<3 in us.
	probe_read_kernel(&v->retranssegs, sizeof(__u32), _(&(tcp->total_retrans)));
}

static inline __attribute__((always_inline)) void
get_socket_stats(struct sock *sk,
		 struct tcpsocketmap_value *socket,
		 struct msg_socket_stats *stats)
{
	struct tcp_sock *tcp = (struct tcp_sock *)sk;
	int i;

	/* Set the time the stats were obtained to allow checking of event ordering */
	stats->ktime = ktime_get_ns();

	/* Copy the create time so that user space can match up the stats. */
	stats->create_ktime = socket->create_time;

	/* Older kernels will not have these statistics. To get a full set of
	 * stats run 4.19 or higher.
	 */
	if (bpf_core_field_exists(tcp->bytes_sent))
		probe_read_kernel(&stats->bytes_sent, sizeof(__u64),
				  _(&(tcp->bytes_sent)));
	if (bpf_core_field_exists(tcp->segs_out))
		probe_read_kernel(&stats->segs_out, sizeof(__u32),
				  _(&(tcp->segs_out)));
	if (bpf_core_field_exists(tcp->bytes_retrans))
		probe_read_kernel(&stats->retransbytes, sizeof(__u64),
				  _(&(tcp->bytes_retrans)));
	if (bpf_core_field_exists(sk->sk_drops))
		probe_read_kernel(&stats->sk_drops, sizeof(__u32), _(&(sk->sk_drops)));

	/* These statistics are known to exist back to 4.12 kernels.
	 */
	probe_read_kernel(&stats->bytes_received, sizeof(__u64),
			  _(&(tcp->bytes_received)));
	probe_read_kernel(&stats->segs_in, sizeof(__u32), _(&(tcp->segs_in)));
	probe_read_kernel(&stats->srtt, sizeof(__u32), _(&(tcp->srtt_us)));
	stats->srtt = stats->srtt / 8; // SRTT is reported <<3 in us.
	probe_read_kernel(&stats->retranssegs, sizeof(__u32),
			  _(&(tcp->total_retrans)));

	//stats->tozerowin populated in-band TCP hook watching for zero window
	stats->tozerowin = socket->zero_window;
#pragma unroll
	for (i = 0; i < 8; i++) {
		stats->rtt_buckets[i] = socket->rtt_buckets[i];
		stats->latency_buckets[i] = socket->latency_buckets[i];
	}
	stats->rtt_sum = socket->rtt_sum;
	stats->latency_sum = socket->latency_sum;
}

static inline __attribute__((always_inline)) void
zero_socket_stats(struct msg_socket_stats *stats)
{
	stats->bytes_sent = 0;
	stats->bytes_received = 0;
	stats->segs_in = 0;
	stats->segs_out = 0;
}

struct ip_ver {
	u8 ihl : 4;
	u8 version : 4;
};

/* get_ip_version returns the skb_head and network_header_offset if the
 * pointers are not NULL.
 */
static inline __attribute__((always_inline)) __u8
get_ip_version(u16 *network_header_offset, void **skbh, struct sk_buff *skb)
{
	u16 network_header_off;
	struct ip_ver ver;
	void *skb_head;

	if (probe_read_kernel(&network_header_off, sizeof(u16),
			      _(&skb->network_header)) < 0)
		return 0;
	if (probe_read_kernel(&skb_head, sizeof(void *), _(&skb->head)) < 0)
		return 0;
	if (probe_read_kernel(&ver, sizeof(ver), skb_head + network_header_off) < 0)
		return 0;
	if (skbh)
		*skbh = skb_head;
	if (network_header_offset)
		*network_header_offset = network_header_off;
	return ver.version;
}

static inline __attribute__((always_inline)) bool
get_ip_header(void *network_header, u32 network_header_size,
	      u16 network_header_off, void *skb_head)
{
	if (probe_read_kernel(network_header, network_header_size,
			      skb_head + network_header_off) < 0)
		return false;
	return true;
}

/* get_transport_header returns the payload_off if the pointer is not NULL. */
static inline __attribute__((always_inline)) bool
get_transport_header(void *transport_header, u32 transport_header_size,
		     int *payload_off, void *skb_head, struct sk_buff *skb,
		     bool tcp)
{
	u16 transport_header_off;

	if (probe_read_kernel(&transport_header_off, sizeof(u16),
			      _(&skb->transport_header)) < 0)
		return false;
	if (probe_read_kernel(transport_header, transport_header_size,
			      skb_head + transport_header_off) < 0)
		return false;
	if (payload_off != 0) {
		if (tcp) {
			// get_tcp_header() is not currently used, so this code
			// is unused/untested.
			struct tcphdr *tcph = (struct tcphdr *)transport_header;
			*payload_off = transport_header_off + (tcph->doff * 4);
		} else {
			// This only works for linear skbs (where data_len == 0).
			// For non-linear skbs, need to access first two fragment
			// pages from struct skb_shared_info.
			*payload_off =
				transport_header_off + transport_header_size;
		}
	}
	return true;
}

static inline __attribute__((always_inline)) bool
get_ip4_header(struct iphdr *ip4_header, u16 network_header_off, void *skb_head)
{
	return get_ip_header((void *)ip4_header, sizeof(struct iphdr),
			     network_header_off, skb_head);
}

static inline __attribute__((always_inline)) bool
get_ip6_header(struct ipv6hdr *ip6_header, u16 network_header_off,
	       void *skb_head)
{
	return get_ip_header((void *)ip6_header, sizeof(struct ipv6hdr),
			     network_header_off, skb_head);
}

/* The IPv6 specification states that the following headers are valid
 * after the fixed header (up to 1 of each, except Destination Options,
 * which is up to 2):
 * Hop-by-Hop Options (0)
 * Routing (43)
 * Fragment (44)
 * Authentication Header (51)
 * Destination Options (60)
 * Encapsulation Security Payload Header (50)
 * Mobilty Header (135)
 * UDP Header (IPPROTO_UDP)
 * TCP Header (IPPROTO_TCP)
 * ICMP6 (IPPROTO_ICMP6)
 * 
 * We choose to ignore Encapsulating Security Payload (ESP) because
 * of complexity (future requirement), Mobility (n/a), Host Identity
 * Protocol (replaces IP addresses), Shim6 Protocol (n/a), and the
 * Reserved header types. If we come across one of these headers, we
 * will return 0 to indicate failure (and no UDP header). Otherwise,
 * we will skip other headers and return the offset of the UDP
 * payload.
 */

#define IPPROTO_ICMP6 58

struct ipv6ext {
	u16 ip_off;
	u16 byte_len;
	u8 header_count;
	u8 curr;
	u8 next;
	u8 len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct ipv6ext);
	__uint(max_entries, 1);
} ipv6ext_heap SEC(".maps");

static inline __attribute__((always_inline)) u8
get_ip6_proto(u16 *payload_off, struct ipv6hdr *ip, u16 network_header_off,
	      void *skb_head, void *data_end, bool lazy, bool kp,
	      unsigned long int *err)
{
	struct ipv6ext *e;
	u8 header_count;
	int zero = 0;

	e = map_lookup_elem(&ipv6ext_heap, &zero);
	if (!e) {
		if (err) {
			*err = IP_ERROR_NO_HEAP;
		}
		return IP_HEADER_ERROR;
	}

	e->ip_off = network_header_off;
	e->curr = 255;
	e->len = 0;
	e->next = ip->nexthdr;

// Maximum 7 valid extensions.
#pragma unroll
	for (header_count = 0; header_count < 7; header_count++) {
		// Correct the length parameter, depending on current extension.
		switch (e->curr) {
		case 255:
			// Fixed header.
			e->byte_len = sizeof(struct ipv6hdr);
			break;
		case 0:
		case 43:
		case 60:
			e->byte_len = (e->len * 8) + 8;
			break;
		case 44:
			e->byte_len = 8;
			break;
		case 51:
			e->byte_len = (e->len * 4) + 8;
			break;
		}

		// Move to next extension.
		e->ip_off += e->byte_len;
		// If next is transport (or an unhandled header, e.g. ESP or Mobility), return it and the optional offset.
		if (e->next != 0 && e->next != 43 && e->next != 44 && e->next != 51 && e->next != 60) {
			if (payload_off)
				*payload_off = e->ip_off;
			return e->next;
		}
		e->curr = e->next;
		// Read next header and current length.
		if (lazy) {
			if (kp) {
				// Kprobe: we have a void *skb_head
				if (probe_read_kernel(&e->next, 2,
						      skb_head + e->ip_off) < 0) {
					if (err) {
						*err = IP_ERROR_IPV6_READ_PROBE;
					}
					return IP_HEADER_ERROR;
				}
			} else {
				// SKB: we have a struct __sk_buff
				if (skb_load_bytes(skb_head, e->ip_off,
						   &e->next, 2) < 0) {
					if (err) {
						*err = IP_ERROR_IPV6_READ_SKB_LOAD;
					}
					return IP_HEADER_ERROR;
				}
			}
		} else {
			if (skb_head + e->ip_off + 2 > data_end) {
				if (err) {
					*err = IP_ERROR_IPV6_READ_SKB_DIRECT;
				}
				return IP_HEADER_ERROR;
			}
			*(u16 *)&e->next = *(u16 *)(skb_head + e->ip_off);
		}
	}
	// Not found transport header.
	if (err) {
		*err = IP_ERROR_IPV6_TOO_MANY_EXT;
	}
	return IP_HEADER_ERROR;
}

/* get_udp_header returns the payload_off if the pointer is not NULL */
static inline __attribute__((always_inline)) bool
get_udp_header(struct udphdr *udp_header, int *payload_off, void *skb_head,
	       struct sk_buff *skb)
{
	return get_transport_header((void *)udp_header, sizeof(struct udphdr),
				    payload_off, skb_head, skb, false);
}

/* get_tcp_header returns the payload_off is the pointer is not NULL */
static inline __attribute__((always_inline)) bool
get_tcp_header(struct tcphdr *tcp_header, int *payload_off, void *skb_head,
	       struct sk_buff *skb)
{
	return get_transport_header((void *)tcp_header, sizeof(struct tcphdr),
				    payload_off, skb_head, skb, true);
}

static inline __attribute__((always_inline)) void
set_ipv6_addr_from_ipv4(u64 *dest, u32 src)
{
	dest[0] = src;
	dest[1] = 0;
}

static inline __attribute__((always_inline)) void copy_ipv6_addr(u64 *dest,
								 u64 *src)
{
	dest[0] = src[0];
	dest[1] = src[1];
}

static inline __attribute__((always_inline)) void
emit_ip_error_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
		    u8 packetver, u8 send, u64 data, unsigned long int err)
{
	struct socketmap_value *process = 0;
	struct msg_ip_event *val;
	int zero = 0;

	val = map_lookup_elem(&ip_error_event_heap, &zero);
	if (!val)
		return;

	if (cookie) {
		u64 c = *cookie;

		process = lookup_socketmap(&c);
	}

	val->common.op = ISO_MSG_OP_IP_ERROR;
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = ktime_get_ns();
	if (process) {
		val->key.pid = process->key.pid;
		val->key.ktime = process->key.ktime;
	} else {
		val->key.pid = 0;
		val->key.ktime = 0;
	}
	val->tuple.ipv6 = ipv6;
	if (ip) {
		if (!ipv6) {
			struct iphdr *ip4 = ip;
			set_ipv6_addr_from_ipv4(val->tuple.saddr, ip4->saddr);
			set_ipv6_addr_from_ipv4(val->tuple.daddr, ip4->daddr);
		} else {
			struct ipv6hdr *ip6 = ip;
			copy_ipv6_addr(val->tuple.saddr, (u64 *)&ip6->saddr);
			copy_ipv6_addr(val->tuple.daddr, (u64 *)&ip6->daddr);
		}
	} else {
		set_ipv6_addr_from_ipv4(val->tuple.saddr, 0);
		set_ipv6_addr_from_ipv4(val->tuple.daddr, 0);
	}
	val->tuple.sport = 0;
	val->tuple.dport = 0;
	if (cookie) {
		val->socket_cookie = *cookie;
	} else {
		val->socket_cookie = 0;
	}
	val->tuple.send = send;
	val->tuple.version_byte = packetver;
	val->ret = err;
	val->version = 0;
	val->duration = data;

	perf_event_output_metric(ctx, ISO_MSG_OP_IP_ERROR, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				 sizeof(struct msg_ip_event));
}

#endif
