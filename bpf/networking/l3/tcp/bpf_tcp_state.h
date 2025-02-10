// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_STATE_H__
#define __BPF_TCP_STATE_H__

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_send_check.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_with_stats_event);
	__uint(max_entries, 1);
} tcp_close_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct tcpsocketmap_value);
	__uint(max_entries, 1);
} tg_sockops_tcpsocket_map SEC(".maps");

static inline __attribute__((always_inline)) struct tcpsocketmap_value *init_tcpsocketmap_value(
	struct msg_execve_key *key, u16 family, u32 flags, u64 create_time, u64 version)
{
	struct tcpsocketmap_value *v;
	int zero = 0;

	v = map_lookup_elem(&tg_sockops_tcpsocket_map, &zero);
	if (!v)
		return 0;

	v->key.pid = key->pid;
	v->key.ktime = key->ktime;
	v->stats.create_time = create_time;
	v->stats.ktime = create_time;
	v->socket_flags = flags;
	v->stats.bytes_sent = 0;
	v->stats.bytes_received = 0;
	v->stats.segs_out = 0;
	v->stats.segs_in = 0;
	v->stats.sk_drops = 0;
	v->stats.zero_window = 0;
	v->ipv6 = (family == AF_INET6);
	v->version = version;
	v->fin_rx = 0;
	v->fin_sent = 0;
	v->last_sent_was_fin = 0;
	v->protocol = IPPROTO_TCP;
	v->closed = 0;
	v->stats.retransbytes = 0;
	v->stats.rtt_sum = 0;
	v->stats.latency_sum = 0;

#pragma unroll
	for (int i = 0; i < 8; i++) {
		v->stats.rtt_buckets[i] = 0;
		v->stats.latency_buckets[i] = 0;
	}

	return v;
}
#endif // __BPF_TCP_STATE_H__
