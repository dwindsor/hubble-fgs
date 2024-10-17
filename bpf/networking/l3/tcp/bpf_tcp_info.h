// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_INFO_H_
#define __BPF_TCP_INFO_H_

#include "vmlinux.h"
#include "api.h"
#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"
#include "../icmp/bpf_icmp_cookie.h"
#include "../udp/bpf_udp_info.h"
#include "bpf_tracing.h"
#include "process/process_endpoint.h"

struct tcpsocketmap_value {
	struct msg_execve_key key;
	struct destination_endpoint_key dst_key;
	__u64 version;
	__u32 socket_flags;
	__u8 ipv6;
	__u8 fin_rx;
	__u8 protocol;
	__u8 closed;
	struct msg_socket_stats stats;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct tcpsocketmap_value);
	__uint(max_entries, 32768);
} tg_tcpsocket_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_tcpsocket_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct tcpsocketmap_value);
	__uint(max_entries, 1);
} tg_tcpsocket_map_heap SEC(".maps");

/* Handle the case where an entry already exists for this cookie. This could
 * be the correct entry (so do nothing) or an incorrect entry (correct it).
 * Neither of these affect the count of entries. The duplicate existing entry
 * condition is most likely to occur on systems where initialisation of an
 * IPv6 UDP socket calls both the v6 and v4 hooks, which appears to happen on
 * some systems but not others.
 */
static inline __attribute__((always_inline)) void
add_tcpsocketmap(u64 *cookie, struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple, bool update_tuple_map)
{
	struct tcpsocketmap_value *existing = (struct tcpsocketmap_value *)map_lookup_elem(&tg_tcpsocket_map, cookie);
	int zero = 0;
	__s64 *cntr;
	int err;

	err = map_update_elem(&tg_tcpsocket_map, cookie, v, 0);
	if (!err) {
		if (!existing && (cntr = (__s64 *)map_lookup_elem(&tg_tcpsocket_map_stats, &zero)))
			*cntr = *cntr + 1;
		if (update_tuple_map)
			add_socket_tuple_map(tuple, cookie);
	}
}

static inline __attribute__((always_inline)) void
del_tcpsocketmap(u64 *cookie)
{
	int err = map_delete_elem(&tg_tcpsocket_map, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_tcpsocket_map_stats, &zero)))
			*cntr = *cntr - 1;
		del_socket_tuple_map(cookie);
	}
}

static inline __attribute__((always_inline)) struct tcpsocketmap_value *
lookup_tcpsocketmap(u64 *cookie)
{
	return (struct tcpsocketmap_value *)map_lookup_elem(&tg_tcpsocket_map, cookie);
}

#endif
