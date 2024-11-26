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

static inline __attribute__((always_inline)) int
check_timestamp(void *ctx, struct timestamp_option *ts_opt, u64 *cookie)
{
	struct latency_protocol_config *tcp_latency = 0;
	struct latency_config *latency_config = 0;
	struct tcpsocketmap_value *socket = 0;
	s64 latency = 0;
	int zero = 0;

	latency_config = (struct latency_config *)map_lookup_elem(&tg_latency_config_map, &zero);
	if (!latency_config) {
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

#ifdef SKB_LOAD_BYTES
static inline __attribute__((always_inline))
#endif
int
tcp_handler_send(struct __sk_buff *skb, u64 *cookie)
{
	__u64 tcp_bytes_sent, tcp_bytes_received;
	struct tcp_send_check_sample_cfg *cfg;
	struct tcpsocketmap_value *socket;
	struct tcp_sock *tcp;
	struct bpf_sock *skp;
	struct sock *sk;
	__u32 rcv_wnd;
	int zero = 0;
	__u8 state;
	__u64 c;

	if (!cookie) {
		emit_ip_error_event(skb, 0, cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_COOKIE);
		return SK_PASS;
	}

	skp = skb->sk;
	if (!skp) {
		emit_ip_error_event(skb, 0, cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_SK);
		return SK_PASS;
	}

	tcp = (struct tcp_sock *)skc_to_tcp_sock(skp);
	sk = (struct sock *)tcp;
	if (!tcp) {
		emit_ip_error_event(skb, 0, cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_TCPSOCK);
		return SK_PASS;
	}

	probe_read_kernel(&state, sizeof(state), _((const void *)&(sk->__sk_common.skc_state)));

	c = *cookie;
	socket = lookup_tcpsocketmap(&c);
	if (unlikely(!socket)) {
		// Don't report an error here if the TCP socket isn't yet active.
		if (tcp_active(state))
			emit_ip_error_event(skb, 0, cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_SOCKET);
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

#ifdef SKB_LOAD_BYTES
static inline __attribute__((always_inline)) int
tcp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	size_t ts_size = sizeof(struct iphdr) + sizeof(struct timestamp_option);

	if (send)
#ifndef NO_SK_TO_TCP
		return tcp_handler_send(skb, cookie);
#else
		return SK_PASS;
#endif

	if (!cookie) {
		emit_ip_error_event(skb, ip, cookie, false, 4, 1, 0, IP_ERROR_TCP_RECV_NO_COOKIE);
		return SK_PASS;
	}
	if (!ip) {
		emit_ip_error_event(skb, 0, cookie, false, 4, 1, 0, IP_ERROR_TCP_RECV_NO_IPHDR);
		return SK_PASS;
	}

	/* Packet has at least enough space for the Timestamp IP Option,
	 * so check if the first option is the Timestamp option that we
	 * add to detect TCP latency.
	 */
	if (ip->ihl >= ts_size / sizeof(u32)) {
		struct timestamp_option ts_opt;

		if (skb_load_bytes(skb, sizeof(struct iphdr), &ts_opt, sizeof(struct timestamp_option)) < 0) {
			emit_ip_error_event(skb, ip, cookie, false, 4, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			return SK_PASS;
		}
		if (ts_opt.type != IPO_TYPE &&
		    ts_opt.magic != bpf_ntohl(IPO_MAGIC_W) &&
		    ts_opt.magic != ts_opt.magic2) {
			return SK_PASS;
		}
		check_timestamp(skb, &ts_opt, cookie);
	}
	return SK_PASS;
}

static inline __attribute__((always_inline)) int
tcp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 payload_off, int send)
{
#ifndef NO_SK_TO_TCP
	if (send)
		return tcp_handler_send(skb, cookie);
#endif
	return SK_PASS;
}

#else
int tcp_handler_ip4_recv(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie)
{
	size_t ts_size = sizeof(struct iphdr) + sizeof(struct timestamp_option);
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct tcpsocketmap_value *socket;
	__u64 c;

	if (!ip) {
		emit_ip_error_event(skb, 0, cookie, false, 4, 1, 0, IP_ERROR_TCP_RECV_NO_IPHDR);
		return SK_PASS;
	}

	if (!cookie)
		return SK_PASS;

	c = *cookie;
	socket = lookup_tcpsocketmap(&c);
	if (socket)
		process_socketmap_recv(socket, skb);

	/* Packet has at least enough space for the Timestamp IP Option,
	 * so check if the first option is the Timestamp option that we
	 * add to detect TCP latency.
	 */
	if (ip->ihl >= ts_size / sizeof(u32)) {
		struct timestamp_option *ts_opt;

		if (data + ts_size > data_end) {
			if (!cookie) {
				emit_ip_error_event(skb, ip, cookie, false, 4, 1, 0, IP_ERROR_TCP_RECV_NO_COOKIE);
				return SK_PASS;
			}
			emit_ip_error_event(skb, ip, cookie, false, ip->version, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			return SK_PASS;
		}
		ts_opt = (struct timestamp_option *)(data + sizeof(struct iphdr));
		if (ts_opt->type != IPO_TYPE ||
		    ts_opt->magic != bpf_ntohl(IPO_MAGIC_W) ||
		    ts_opt->magic != ts_opt->magic2) {
			return SK_PASS;
		}
		check_timestamp(skb, ts_opt, cookie);
	}
	return SK_PASS;
}

int tcp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	if (send)
		return tcp_handler_send(skb, cookie);

	return tcp_handler_ip4_recv(skb, ip, cookie);
}

int tcp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 payload_off, int send)
{
	if (send)
		return tcp_handler_send(skb, cookie);
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES
#endif //__BPF_TCP_RECV_H_
