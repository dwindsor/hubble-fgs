// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_RECV_H_
#define __BPF_TCP_RECV_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_latency.h"
#include "bpf_process_network_watermarks.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_send_check.h"
#include "lib/address_family.h"
#include "bpf_tracing.h"
#include "bpf_tcp_info.h"
#include "process/process_tree.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tcp_cookie_heap SEC(".maps");

static inline __attribute__((always_inline)) bool
get_tcp_fin(struct __sk_buff *skb, void *ip, __u64 tcp_offset, __u64 *cookie, bool ipv6)
{
	__u64 data_end = skb->data_end;
	__u64 data = skb->data;
	struct tcphdr *tcp;
	struct tcphdr stor;

	if (data + (tcp_offset & 0x0fff) + sizeof(struct tcphdr) > data_end) {
		if (skb_load_bytes(skb, tcp_offset, &stor, sizeof(struct tcphdr)) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6, 0, 1, 0, IP_ERROR_INET_READ_TCP);
			return false;
		}
		tcp = &stor;
	} else {
		tcp = (struct tcphdr *)(data + (tcp_offset & 0xfff));
	}
	return tcp->fin;
}

static inline __attribute__((always_inline)) int
tcp_check_fin_rx(struct __sk_buff *skb, void *ip, __u64 tcp_offset, __u64 *cookie, bool ipv6)
{
	bool tcpfin = get_tcp_fin(skb, ip, tcp_offset, cookie, ipv6);
	struct tcp_sock *tcp;
	__u64 bytes_received;
	__u64 *exists;
	__u64 c;

	// Only handle FIN datagrams.
	if (!tcpfin)
		return SK_PASS;

	if (!cookie)
		return SK_PASS;

	c = *cookie;
	tcp = (struct tcp_sock *)c;

	// If we've received a FIN, then we can assume no more data from the
	// remote. So let's store the bytes_received for this socket. Future
	// stats collection for this socket will use this value instead of
	// the one in the TCP stack. This avoids counting an extra byte for
	// an ACK of a FIN.

	// First check if we've already received a FIN for this socket (we delete
	// them on socket destruction).
	exists = map_lookup_elem(&tg_tcp_finrx_map, &c);
	if (exists)
		return SK_PASS;
	// Otherwise, store the current bytes_received.
	probe_read_kernel(&bytes_received, sizeof(bytes_received), _(&tcp->bytes_received));
	map_update_elem(&tg_tcp_finrx_map, &c, &bytes_received, 0);

	return SK_PASS;
}

static inline __attribute__((always_inline)) int
check_timestamp(void *ctx, struct timestamp_option *ts_opt, u64 *cookie)
{
	struct latency_protocol_config *tcp_latency = 0;
	struct latency_config *latency_config = 0;
	struct tcpsocketmap_value *socket = 0;
	s64 latency = 0;
	int zero = 0;

	latency_config = (struct latency_config *)map_lookup_elem(&tg_latency_config_map, &zero);
	if (!latency_config || !latency_config->tcp.enable) {
		return SK_PASS;
	}

	if (cookie) {
		__u64 c = *cookie;

		socket = lookup_tcpsocketmap(&c);
	}

	if (!socket) {
		emit_ip_error_event(ctx, 0, cookie, false, 0, 0, 0, IP_ERROR_TCP_TIMESTAMP_NO_SOCKET);
		return SK_PASS;
	}

	latency = calc_latency(latency_config->boot_ns,
			       bpf_ntohl(ts_opt->timestamp_low),
			       bpf_ntohl(ts_opt->timestamp_high));
	tcp_latency = &latency_config->tcp;

	add_latency(tcp_latency, socket->stats.latency_buckets, &socket->stats.latency_sum, latency);

	return SK_PASS;
}

int tcp_handler_send(struct __sk_buff *skb)
{
	__u64 tcp_bytes_sent, tcp_bytes_received;
	struct tcp_send_check_sample_cfg *cfg;
	struct tcpsocketmap_value *socket;
	struct handler_vars *vars;
	struct tcp_sock *tcp;
	struct sock *sk;
	__u32 rcv_wnd;
	int zero = 0;
	__u8 state;
	__u64 c;

	vars = (struct handler_vars *)map_lookup_elem(&dispatcher_heap, &zero);
	if (!vars)
		return SK_PASS;

	c = vars->cookie;
	// We can just cast pointers here because a struct bpf_sock * points to the same location
	// as a struct sock * (with BPF magic behind the scenes to provide different functionality).
	tcp = (struct tcp_sock *)c;
	sk = (struct sock *)tcp;
	if (!tcp) {
		emit_ip_error_event(skb, 0, &vars->cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_TCPSOCK);
		return SK_PASS;
	}

	probe_read_kernel(&state, sizeof(state), _((const void *)&(sk->__sk_common.skc_state)));

	socket = lookup_tcpsocketmap(&c);
	if (unlikely(!socket)) {
		// Don't report an error here if the TCP socket isn't yet active.
		if (tcp_active(state))
			emit_ip_error_event(skb, 0, &vars->cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_SOCKET);
		return SK_PASS;
	}

	probe_read_kernel(&tcp_bytes_sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	probe_read_kernel(&tcp_bytes_received, sizeof(__u64), _(&(tcp->bytes_received)));
	probe_read_kernel(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));

	if (!rcv_wnd && state == TCP_ESTABLISHED)
		socket->stats.zero_window++;

	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(&tg_tcp_send_check_sampler, &zero);
	if (cfg && cfg->watermarksEnable && socket->key.pid != 0) {
		struct socketmap_value process = {
			.key.ktime = socket->key.ktime,
			.key.pid = socket->key.pid,
		};
		struct process_network_watermarks_config c = {
			.avg_window_size_ms =
				cfg->watermarksAvgWindowSize,
			.window_size =
				cfg->watermarksWindowSizeNs,
			.burst_trigger_mult =
				cfg->watermarksBurstTriggerMult,
			.dip_trigger_mult =
				cfg->watermarksDipTriggerMult,
		};

		if (tcp_bytes_sent > socket->stats.bytes_sent) {
			process_network_watermarks(
				skb, &process, IPPROTO_TCP,
				WATERMARKS_KEY_SEND_EGRESS,
				tcp_bytes_sent - socket->stats.bytes_sent,
				&c);
		}
		if (tcp_bytes_received > socket->stats.bytes_received) {
			process_network_watermarks(
				skb, &process, IPPROTO_TCP,
				WATERMARKS_KEY_SEND_INGRESS,
				tcp_bytes_received - socket->stats.bytes_received,
				&c);
		}
	}
	cgrp_tcp_socketmap_stats(sk, socket);
#ifndef SKB_LOAD_BYTES
	return process_socketmap_send(socket, skb);
#endif
	return SK_PASS;
}

int tcp_handler_ip4_recv(struct __sk_buff *skb)
{
	size_t ts_size = sizeof(struct iphdr) + sizeof(struct timestamp_option);
	struct timestamp_option *ts_opt = 0, ts_opt_tmp;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct handler_vars *vars;
	struct iphdr *ip;
	int err;

#ifndef SKB_LOAD_BYTES
	struct tcpsocketmap_value *socket;
	__u64 c;
#endif

	vars = (struct handler_vars *)map_lookup_elem(&dispatcher_heap, &zero);
	if (!vars)
		return SK_PASS;
	ip = &vars->ip;

#ifndef SKB_LOAD_BYTES
	c = vars->cookie;
	socket = lookup_tcpsocketmap(&c);
	if (socket) {
		int verdict = process_socketmap_recv(socket, skb);

		if (verdict == SK_DROP)
			return SK_DROP;
	}
#endif

	/* Packet has at least enough space for the Timestamp IP Option,
	 * so check if the first option is the Timestamp option that we
	 * add to detect TCP latency.
	 */
	if (ip->ihl >= ts_size / sizeof(u32)) {
		if (data + ts_size <= data_end) {
			ts_opt = (struct timestamp_option *)(data + sizeof(struct iphdr));
		} else {
			err = skb_load_bytes(skb, sizeof(struct iphdr), &ts_opt_tmp, sizeof(struct timestamp_option));
			if (err < 0) {
				emit_ip_error_event(
					skb, &ip, &vars->cookie, false,
					false, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			} else {
				ts_opt = &ts_opt_tmp;
			}
		}

		if (ts_opt && ts_opt->type == IPO_TYPE &&
		    ts_opt->magic == bpf_ntohl(IPO_MAGIC_W) &&
		    ts_opt->magic == ts_opt->magic2)
			check_timestamp(skb, ts_opt, &vars->cookie);
	}
	return SK_PASS;
}

#ifdef NO_CGROUP_PROBE_READ
int tcp_handler_ip4(struct __sk_buff *skb, int send)
{
	if (send)
		return SK_PASS;
	return tcp_handler_ip4_recv(skb);
}

int tcp_handler_ip6(struct __sk_buff *skb, u16 payload_off, int send)
{
	return SK_PASS;
}
#else
int tcp_handler_ip4(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct handler_vars *vars;
	struct iphdr *ip;
	int zero = 0;

	vars = (struct handler_vars *)map_lookup_elem(&dispatcher_heap, &zero);
	if (!vars)
		return SK_PASS;

	if (data + sizeof(struct iphdr) > data_end)
		ip = &vars->ip;
	else
		ip = (struct iphdr *)data;

	if (send)
		return tcp_handler_send(skb);

	tcp_check_fin_rx(skb, ip, ip->ihl * sizeof(__u32), &vars->cookie, false);
	return tcp_handler_ip4_recv(skb);
}
int tcp_handler_ip6(struct __sk_buff *skb, u16 payload_off, int send)
{
	struct handler_vars *vars;
	struct ipv6hdr *ip6;

	vars = (struct handler_vars *)map_lookup_elem(&dispatcher_heap, &zero);
	if (!vars)
		return SK_PASS;
	ip6 = &vars->ip6;

	if (send)
		return tcp_handler_send(skb);

	tcp_check_fin_rx(skb, ip6, payload_off, &vars->cookie, true);
	return SK_PASS;
}
#endif

#endif //__BPF_TCP_RECV_H_
