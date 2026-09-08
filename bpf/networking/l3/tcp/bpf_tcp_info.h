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
#include "l3_config.h"

struct tcpsocketmap_value {
	struct msg_execve_key key;
	struct destination_endpoint_key dst_key;
	__u64 version;
	struct msg_ip_tuple tuple;
	__u32 socket_flags;
	__u8 closed;
	__u8 deny;
	__u16 pad;
	struct msg_socket_stats stats;
	/* Policy generation the cached deny was resolved against, compared by
	 * policy_gen_stale in process_tree.h.
	 */
	__u32 policy_gen;
	__u32 pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct tcpsocketmap_value);
	__uint(max_entries, 1); // will be resized by user space
} tg_l3_tcpsk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_l3_tcpsk_stats SEC(".maps");

/* Separate map to hold the bytes_received at the time a FIN was received.
 * This allows us to avoid including the potential extra byte that appears
 * in the stack's bytes_received counter if it ACKs a FIN.
 * By storing this value in a separate map, we avoid the race between
 * the accept (sock graft) program adding an entry, and the FIN arriving
 * at a similar time. Once written, we will use this value for the
 * bytes_received every time we collect stats.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 1); // will be resized by user space
} tg_l3_tcp_finrx SEC(".maps");

/* Handle the case where an entry already exists for this cookie. This could
 * be the correct entry (so do nothing) or an incorrect entry (correct it).
 * Neither of these affect the count of entries. The duplicate existing entry
 * condition is most likely to occur on systems where initialisation of an
 * IPv6 UDP socket calls both the v6 and v4 hooks, which appears to happen on
 * some systems but not others.
 */
static inline __attribute__((always_inline)) void
add_tcpsocketmap(u64 *cookie, struct tcpsocketmap_value *v, bool update_tuple_map)
{
	struct tcpsocketmap_value *existing = (struct tcpsocketmap_value *)map_lookup_elem(&tg_l3_tcpsk, cookie);
	int zero = 0;
	__s64 *cntr;
	int err;

	err = map_update_elem(&tg_l3_tcpsk, cookie, v, 0);
	if (!err) {
		if (!existing && (cntr = (__s64 *)map_lookup_elem(&tg_l3_tcpsk_stats, &zero)))
			*cntr = *cntr + 1;
		if (update_tuple_map)
			add_socket_tuple_map(&v->tuple, cookie);
	}
}

static inline __attribute__((always_inline)) void
del_tcpsocketmap(u64 *cookie)
{
	int err = map_delete_elem(&tg_l3_tcpsk, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_l3_tcpsk_stats, &zero)))
			*cntr = *cntr - 1;
		del_socket_tuple_map(cookie);
	}
}

static inline __attribute__((always_inline)) struct tcpsocketmap_value *
lookup_tcpsocketmap(u64 *cookie)
{
	return (struct tcpsocketmap_value *)map_lookup_elem(&tg_l3_tcpsk, cookie);
}

static inline __attribute__((always_inline)) bool
tcp_active(u8 state)
{
	switch (state) {
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_CLOSE:
		return false;
	}
	return true;
}
#endif
