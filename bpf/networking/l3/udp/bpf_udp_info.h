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
#include "config.h"
#include "bpf_ktime.h"
#include "bpf_cookie.h"
#include "bpf_event_map.h"

/* UDP Info maintains the statistics associated with a UDP "session".
 * Here we have the map and helper routines to setup keys and values.
 */

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

/* Clock is defined in linux/time.h */
#define CLOCK_REALTIME	0
#define CLOCK_MONOTONIC 1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_key);
	__uint(max_entries, 1);
} tg_p_l3_udp_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct udp_info_key);
	__type(value, struct udp_info_value);
	__uint(max_entries, MAX_UDP_ENDPOINTS);
} tg_l3_udpsk SEC(".maps");

// We specifically do not use *_stats as the map name to hold the counts of tg_l3_udpsk
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
} tg_l3_udpsk_cnt SEC(".maps");

#ifdef USE_BPF_TIMER
// Store timers to expire the tg_l3_udpsk entries
struct udp_timer_value {
	struct bpf_timer expires;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct udp_info_key);
	__type(value, struct udp_timer_value);
	__uint(max_entries, MAX_UDP_ENDPOINTS);
} tg_l3_udp_tmr SEC(".maps");
#endif

/* Store the latest pseudo-socket version number. Each pseudo-socket receives a
 * new global version number, unique to each pseudo-socket.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} tg_l3_udpsk_ver SEC(".maps");

static inline __attribute__((always_inline)) u64
pseudo_socket_inc_version()
{
	u64 *version;
	u32 zero = 0;

	version = (u64 *)map_lookup_elem(&tg_l3_udpsk_ver, &zero);
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
} tg_h_udp_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_value);
	__uint(max_entries, 1);
} tg_h_udp_value SEC(".maps");

static inline __attribute__((always_inline)) int
dns_source_port_match(u16 *ports, u16 port)
{
	if (ports[0] == port || (ports[1] && ports[1] == port) ||
	    (ports[2] && ports[2] == port) || (ports[3] && ports[3] == port))
		return 1;
	return 0;
}

static inline __attribute__((always_inline)) void
udp_key(struct udp_info_key *key, bool *dns_combined, u64 *cookie, u64 version, struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *config;

	if (!l3cfg)
		return;
	config = &l3cfg->udp;

	if (send) {
		if (!config->dns_stats_per_socket && dns_source_port_match(config->dns_ports, bpf_ntohs(udp->source))) {
			*dns_combined = true;
			// For DNS we zero the remote IP address and remote port.
			key->tuple.daddr[0] = 0;
			key->tuple.daddr[1] = 0;
			key->tuple.dport = 0;
		}
		if (!ipv6) {
			key->tuple.saddr[0] = ip->saddr;
			key->tuple.saddr[1] = 0;
			if (!*dns_combined) {
				key->tuple.daddr[0] = ip->daddr;
				key->tuple.daddr[1] = 0;
			}
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			if (!*dns_combined) {
				addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
				key->tuple.daddr[0] = addr[0];
				key->tuple.daddr[1] = addr[1];
			}
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->source);
		if (!*dns_combined)
			key->tuple.dport = bpf_ntohs(udp->dest);
	} else {
		if (!config->dns_stats_per_socket && dns_source_port_match(config->dns_ports, bpf_ntohs(udp->dest))) {
			*dns_combined = true;
			// For DNS we zero the remote IP addresses and remote port.
			key->tuple.daddr[0] = 0;
			key->tuple.daddr[1] = 0;
			key->tuple.dport = 0;
		}
		if (!ipv6) {
			key->tuple.saddr[0] = ip->daddr;
			key->tuple.saddr[1] = 0;
			if (!*dns_combined) {
				key->tuple.daddr[0] = ip->saddr;
				key->tuple.daddr[1] = 0;
			}
			key->tuple.ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->tuple.saddr[0] = addr[0];
			key->tuple.saddr[1] = addr[1];
			if (!*dns_combined) {
				addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
				key->tuple.daddr[0] = addr[0];
				key->tuple.daddr[1] = addr[1];
			}
			key->tuple.ipv6 = true;
		}
		// In the key, the port is always host order.
		key->tuple.sport = bpf_ntohs(udp->dest);
		if (!*dns_combined)
			key->tuple.dport = bpf_ntohs(udp->source);
	}
	key->cookie = *cookie;
	key->version = version;
	key->tuple.proto = IPPROTO_UDP;
	key->tuple.send = 0;
	key->tuple.version_byte = 0;
	key->tuple.conn_id = 0;
}

static inline __attribute__((always_inline)) void
udp_info_init(struct udp_info_value *v)
{
	v->pid = 0;
	v->pid_ktime = 0;
	v->sk_drops = 0;
	WRITE_ONCE(v->ktime, tg_get_ktime());
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
	WRITE_ONCE(v->ktime, tg_get_ktime());
}

static inline __attribute__((always_inline)) void
update_rx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->rx_bytes, len);
	__sync_fetch_and_add(&v->segs_in, 1);
	WRITE_ONCE(v->ktime, tg_get_ktime());
}

#ifdef USE_BPF_TIMER
static int remove_udp_entry(void *map, struct udp_info_key *k, struct udp_info_value *v)
{
	int err = map_delete_elem(&tg_l3_udpsk, k);
	int zero = 0;
	__s64 *cntr;

	if (!err) {
		cntr = (__s64 *)map_lookup_elem(&tg_l3_udpsk_cnt, &zero);
		if (cntr)
			*cntr = *cntr - 1;
	}

	map_delete_elem(map, k);
	return 0;
}

static inline __attribute__((always_inline)) void
__init_timer(void *map, struct bpf_timer *timer)
{
	if (timer_init(timer, map, CLOCK_MONOTONIC) < 0)
		return;
	timer_set_callback(timer, remove_udp_entry);
}

static inline __attribute__((always_inline)) void
__set_timer(void *map, struct bpf_timer *timer, u64 nsec)
{
	if (timer_start(timer, nsec, 0) < 0) {
		__init_timer(map, timer);
		timer_start(timer, nsec, 0);
	}
}

__attribute__((noinline)) int
update_udp_timer()
{
	struct udp_timer_value init_timer = {};
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *udp_cfg;
	struct udp_timer_value *timer;
	struct udp_info_key *k;
	int zero = 0;

	k = (struct udp_info_key *)map_lookup_elem(&tg_p_l3_udp_key, &zero);
	if (!k)
		return 0;

	if (!l3cfg)
		return 0;
	udp_cfg = &l3cfg->udp;
	if (!udp_cfg->idle_timeout)
		return 0;
	timer = map_lookup_elem(&tg_l3_udp_tmr, k);
	if (!timer) {
		map_update_elem(&tg_l3_udp_tmr, k, &init_timer, 0);
		timer = map_lookup_elem(&tg_l3_udp_tmr, k);
		if (!timer)
			return 0;
	}
	__set_timer(&tg_l3_udp_tmr, (struct bpf_timer *)&timer->expires, udp_cfg->idle_timeout);
	return 0;
}

__attribute__((noinline)) int
set_udp_timer()
{
	struct udp_timer_value init_timer = {};
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *udp_cfg;
	struct udp_timer_value *timer;
	struct udp_info_key *k;
	int zero = 0;

	k = (struct udp_info_key *)map_lookup_elem(&tg_p_l3_udp_key, &zero);
	if (!k)
		return 0;

	if (!l3cfg)
		return 0;
	udp_cfg = &l3cfg->udp;
	if (!udp_cfg->idle_timeout)
		return 0;
	map_update_elem(&tg_l3_udp_tmr, k, &init_timer, 0);
	timer = (struct udp_timer_value *)map_lookup_elem(&tg_l3_udp_tmr, k);
	if (!timer)
		return 0;
	__init_timer(&tg_l3_udp_tmr, (struct bpf_timer *)&timer->expires);
	__set_timer(&tg_l3_udp_tmr, (struct bpf_timer *)&timer->expires, udp_cfg->idle_timeout);

	return 0;
}
#endif

static inline __attribute__((always_inline)) void
add_udp_map(struct udp_info_key *key, struct udp_info_value *value)
{
	struct udp_info_value *existing = (struct udp_info_value *)map_lookup_elem(&tg_l3_udpsk, key);
	int zero = 0;
	__s64 *cntr;
	int err;

	err = map_update_elem(&tg_l3_udpsk, key, value, 0);
	if (!err && !existing && (cntr = (__s64 *)map_lookup_elem(&tg_l3_udpsk_cnt, &zero)))
		*cntr = *cntr + 1;
#ifdef USE_BPF_TIMER
	set_udp_timer();
#endif
}

#endif
