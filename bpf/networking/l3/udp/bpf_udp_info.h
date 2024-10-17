// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_INFO_H_
#define __BPF_UDP_INFO_H_

#include "networkmsg.h"

/* UDP Info maintains the statistics associated with a UDP "session".
 * Here we have the map and helper routines to setup keys and values.
 */

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct udp_info_key);
	__type(value, struct udp_info_value);
	__uint(max_entries, MAX_UDP_ENDPOINTS);
} tg_udp_map SEC(".maps");

struct udp_info_key {
	u64 cookie;
	struct msg_ip_tuple tuple;
	u64 version;
}; // All fields aligned so no 'packed' attribute.

struct udp_info_value {
	u64 tx_bytes;
	u64 rx_bytes;
	u64 segs_in;
	u64 segs_out;
	u64 ktime;
	u64 pid_ktime;
	u32 pid;
	u32 sk_drops;
	u64 buckets[8];
	u64 latency_sum;
	u64 create_time;
}; // All fields aligned so no 'packed' attribute.

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_key);
	__uint(max_entries, 1);
} tg_udp_key_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_value);
	__uint(max_entries, 1);
} tg_udp_value_heap SEC(".maps");

static inline __attribute__((always_inline)) void
udp_key(struct udp_info_key *key, u64 *cookie, u64 version, struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	if (send) {
		if (!ipv6) {
			key->tuple.saddr[0] = ip->saddr;
			key->tuple.saddr[1] = 0;
			key->tuple.daddr[0] = ip->daddr;
			key->tuple.daddr[1] = 0;
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->tuple.daddr[0] = addr[0];
			key->tuple.daddr[1] = addr[1];
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->source);
		key->tuple.dport = bpf_ntohs(udp->dest);
	} else {
		if (!ipv6) {
			key->tuple.saddr[0] = ip->daddr;
			key->tuple.saddr[1] = 0;
			key->tuple.daddr[0] = ip->saddr;
			key->tuple.daddr[1] = 0;
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->tuple.daddr[0] = addr[0];
			key->tuple.daddr[1] = addr[1];
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->dest);
		key->tuple.dport = bpf_ntohs(udp->source);
	}
	key->cookie = *cookie;
	key->version = version;
	key->tuple.proto = IPPROTO_UDP;
}

static inline __attribute__((always_inline)) void
udp_info_init(struct udp_info_value *v)
{
	v->pid = 0;
	v->pid_ktime = 0;
	v->sk_drops = 0;
	WRITE_ONCE(v->ktime, ktime_get_ns());
	v->create_time = 0;
#pragma unroll
	for (int i = 0; i < 8; i++) {
		v->buckets[i] = 0;
	}
	v->latency_sum = 0;
}

static inline __attribute__((always_inline)) void
udp_info_tx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->tx_bytes = len;
	v->rx_bytes = 0;

	v->segs_out = len ? 1 : 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
udp_info_rx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->tx_bytes = 0;
	v->rx_bytes = len;

	v->segs_out = 0;
	v->segs_in = 1;
}

static inline __attribute__((always_inline)) void
update_tx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->tx_bytes, len);
	__sync_fetch_and_add(&v->segs_out, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_rx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->rx_bytes, len);
	__sync_fetch_and_add(&v->segs_in, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

#endif
