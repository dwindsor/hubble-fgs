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
#include "lib/address_family.h"
#include "bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tcp_cookie_heap SEC(".maps");

static inline __attribute__((always_inline)) int
check_timestamp(struct timestamp_option *ts_opt, u64 *cookie)
{
	struct latency_config *latency_config = 0;
	struct latency_protocol_config *tcp_latency = 0;
	struct socketmap_value *process;
	int zero = 0;
	s64 latency = 0;

	latency_config = (struct latency_config *)map_lookup_elem(&tg_latency_config_map, &zero);
	if (!latency_config) {
		return 1;
	}

	process = lookup_socketmap(cookie);
	if (!process) {
		return 1;
	}

	latency = calc_latency(latency_config->boot_ns,
			       bpf_ntohl(ts_opt->timestamp_low),
			       bpf_ntohl(ts_opt->timestamp_high));
	tcp_latency = &latency_config->tcp;

	add_latency(tcp_latency, process->latency_buckets, &process->latency_sum, latency);

	return 1;
}

static inline __attribute__((always_inline)) int
tcp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 off, int send)
{
	return SK_PASS;
}

#ifdef SKB_LOAD_BYTES
static inline __attribute__((always_inline)) int
tcp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	size_t ts_size = sizeof(struct iphdr) + sizeof(struct timestamp_option);

	if (send)
		return SK_PASS;

	if (!cookie)
		return SK_PASS;
	if (!ip)
		return SK_PASS;

	/* Packet has at least enough space for the Timestamp IP Option,
	 * so check if the first option is the Timestamp option that we
	 * add to detect TCP latency.
	 */
	if (ip->ihl >= ts_size / sizeof(u32)) {
		struct timestamp_option ts_opt;

		if (skb_load_bytes(skb, sizeof(struct iphdr), &ts_opt, sizeof(struct timestamp_option)) < 0) {
			emit_ip_error_event(skb, &ip, cookie, false, 4, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			return SK_PASS;
		}
		if (ts_opt.type != IPO_TYPE &&
		    ts_opt.magic != bpf_ntohl(IPO_MAGIC_W) &&
		    ts_opt.magic != ts_opt.magic2) {
			return SK_PASS;
		}
		check_timestamp(&ts_opt, cookie);
	}
	return SK_PASS;
}
#else
int tcp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	size_t ts_size = sizeof(struct iphdr) + sizeof(struct timestamp_option);

	if (send)
		return SK_PASS;

	if (!cookie)
		return SK_PASS;
	if (!ip)
		return SK_PASS;

	/* Packet has at least enough space for the Timestamp IP Option,
	 * so check if the first option is the Timestamp option that we
	 * add to detect TCP latency.
	 */
	if (ip->ihl >= ts_size / sizeof(u32)) {
		struct timestamp_option *ts_opt;

		if (data + ts_size > data_end) {
			emit_ip_error_event(skb, ip, cookie, false, ip->version, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			return SK_PASS;
		}
		ts_opt = (struct timestamp_option *)(data + sizeof(struct iphdr));
		if (ts_opt->type != IPO_TYPE ||
		    ts_opt->magic != bpf_ntohl(IPO_MAGIC_W) ||
		    ts_opt->magic != ts_opt->magic2) {
			return SK_PASS;
		}
		check_timestamp(ts_opt, cookie);
	}
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES
#endif //__BPF_TCP_RECV_H_
