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
#include "bpf_udp_config.h"

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

// We specifically do not use *_stats as the map name to hold the counts of tg_udp_map
// usage because we increment from BPF but decrement from user space. If we did use
// *_stats then we'd have a race condition where both BPF and user space update the
// map at the same time. We avoid this by counting increments in a PERCPU map in BPF
// and decrements in a int64 in user space and we add them together. We therefore don't
// want to use *_stats as the map name as this would be automatically summed and
// exported as a metric and it would be mostly meaningless.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_udp_map_count SEC(".maps");

/* Store the latest pseudo-socket version number. Each pseudo-socket receives a
 * new global version number, unique to each pseudo-socket.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} tg_psver_map SEC(".maps");

static inline __attribute__((always_inline)) u64
pseudo_socket_inc_version()
{
	u64 *version;
	u32 zero = 0;

	version = (u64 *)map_lookup_elem(&tg_psver_map, &zero);
	if (!version)
		return 0;
	__sync_fetch_and_add(version, 1);
	return *version;
}

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
	u64 ps_version; // pseudo-socket version
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

static inline __attribute__((always_inline)) int
dns_source_port_match(u16 *ports, u16 port)
{
	if (ports[0] == port || ports[1] == port ||
	    ports[2] == port || ports[3] == port)
		return 1;
	return 0;
}

static inline __attribute__((always_inline)) void
udp_key(struct udp_info_key *key, bool *dnsCombined, u64 *cookie, u64 version, struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	struct udp_sensor_config *config = get_udp_config();

	if (send) {
		if (config && !config->dnsStatsPerSocket && dns_source_port_match(config->dnsPorts, bpf_ntohs(udp->source))) {
			*dnsCombined = true;
			// For DNS we zero the remote IP address and remote port.
			key->tuple.daddr[0] = 0;
			key->tuple.daddr[1] = 0;
			key->tuple.dport = 0;
		}
		if (!ipv6) {
			key->tuple.saddr[0] = ip->saddr;
			key->tuple.saddr[1] = 0;
			if (!*dnsCombined) {
				key->tuple.daddr[0] = ip->daddr;
				key->tuple.daddr[1] = 0;
			}
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			if (!*dnsCombined) {
				addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
				key->tuple.daddr[0] = addr[0];
				key->tuple.daddr[1] = addr[1];
			}
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->source);
		if (!*dnsCombined)
			key->tuple.dport = bpf_ntohs(udp->dest);
	} else {
		if (config && !config->dnsStatsPerSocket && dns_source_port_match(config->dnsPorts, bpf_ntohs(udp->dest))) {
			*dnsCombined = true;
			// For DNS we zero the remote IP addresses and remote port.
			key->tuple.daddr[0] = 0;
			key->tuple.daddr[1] = 0;
			key->tuple.dport = 0;
		}
		if (!ipv6) {
			key->tuple.saddr[0] = ip->daddr;
			key->tuple.saddr[1] = 0;
			if (!*dnsCombined) {
				key->tuple.daddr[0] = ip->saddr;
				key->tuple.daddr[1] = 0;
			}
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			if (!*dnsCombined) {
				addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
				key->tuple.daddr[0] = addr[0];
				key->tuple.daddr[1] = addr[1];
			}
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->dest);
		if (!*dnsCombined)
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
	v->ps_version = pseudo_socket_inc_version();
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

static inline __attribute__((always_inline)) void
add_udp_map(struct udp_info_key *key, struct udp_info_value *value)
{
	struct udp_info_value *existing = (struct udp_info_value *)map_lookup_elem(&tg_udp_map, key);
	int zero = 0;
	__s64 *cntr;
	int err;

	err = map_update_elem(&tg_udp_map, key, value, 0);
	if (!err && !existing && (cntr = (__s64 *)map_lookup_elem(&tg_udp_map_count, &zero)))
		*cntr = *cntr + 1;
}

#endif