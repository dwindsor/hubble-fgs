// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_COOKIE_H_
#define __BPF_COOKIE_H_

#include "vmlinux.h"
#include "api.h"
#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"
#include "l3/icmp/bpf_icmp_cookie.h"
#include "l3/udp/bpf_udp_info.h"

struct socketmap_value {
	struct msg_execve_key key;
	__u64 create_time;
	__u32 version;
	__u8 protocol;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct socketmap_value);
	__uint(max_entries, 32768);
} tg_socket_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_socket_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct socketmap_value);
	__uint(max_entries, 1);
} tg_socket_map_heap SEC(".maps");

// get socket cookie helper
static inline __attribute__((always_inline)) u64 get_cookie(struct sock *sk)
{
	u64 cookie = 0;
	probe_read_kernel(&cookie, sizeof(cookie), _(&(sk->__sk_common.skc_cookie)));
	return cookie;
}

static inline __attribute__((always_inline)) u64
get_cookie_or_sk(struct sock *sk)
{
	u64 cookie = get_cookie(sk);
	if (cookie) {
		return cookie;
	} else {
		return (u64)sk;
	}
}

#ifdef SK_MSG
static inline __attribute__((always_inline)) u64
get_cookie_or_sk_from_msg(ctx_md *msg)
{
	struct sock *sk = (struct sock *)msg->sk;
	u64 cookie = get_socket_cookie(msg);
	if (cookie) {
		return cookie;
	} else {
		return (u64)sk;
	}
}
#else
static inline __attribute__((always_inline)) u64
get_cookie_or_sk_from_msg(struct __sk_buff *skb)
{
	u64 cookie = get_socket_cookie(skb);
	if (cookie) {
		return cookie;
	} else {
		return (u64)skb->sk;
	}
}

#endif

/* Unfortunately, clang will try to do the obvious direct write
 * written as 'key->cookie = (u64)skb->sk' using 8 1B writes
 * which then tries to do a shift over skb->sk which the verifier
 * recognizes is actually a sock type and throws an error because
 * it doesn't want users to manipulate pointers with partial reads
 * and writes. I can't think why the verifier doesn't just clear
 * the register type info and mark it unknown, but we have to live
 * with the verifier as is and can fix upstream. So force clang
 * to do simple write with asm.
 */
static inline __attribute__((always_inline)) void write_cookie(u64 *cookie,
							       u64 value)
{
	asm volatile("*(u64 *)%[cookie] = %[value];\n"
		     : [cookie] "+m"(*cookie)
		     : [value] "r"(value)
		     :);
}

/* Handle the case where an entry already exists for this cookie. This could
 * be the correct entry (so do nothing) or an incorrect entry (correct it).
 * Neither of these affect the count of entries. The duplicate existing entry
 * condition is most likely to occur on systems where initialisation of an
 * IPv6 UDP socket calls both the v6 and v4 hooks, which appears to happen on
 * some systems but not others.
 */
static inline __attribute__((always_inline)) void
add_socketmap(u64 *cookie, struct socketmap_value *v, bool update_tuple_map)
{
	struct socketmap_value *existing = (struct socketmap_value *)map_lookup_elem(&tg_socket_map, cookie);
	int err;
	int zero = 0;
	__s64 *cntr;

	if (existing) {
		if (existing->key.pid == v->key.pid && existing->key.ktime == v->key.ktime && existing->version == v->version)
			return;
		map_delete_elem(&tg_socket_map, cookie);
	}

	err = map_update_elem(&tg_socket_map, cookie, v, 0);
	if (!err) {
		if (!existing && (cntr = (__s64 *)map_lookup_elem(&tg_socket_map_stats, &zero)))
			*cntr = *cntr + 1;
		if (update_tuple_map)
			add_socket_tuple_map(cookie);
	}
}

static inline __attribute__((always_inline)) void
del_socketmap(u64 *cookie)
{
	int err = map_delete_elem(&tg_socket_map, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_socket_map_stats, &zero)))
			*cntr = *cntr - 1;
		del_socket_tuple_map(cookie);
	}
}

static inline __attribute__((always_inline)) struct socketmap_value *
lookup_socketmap(u64 *cookie)
{
	return (struct socketmap_value *)map_lookup_elem(&tg_socket_map, cookie);
}

/* Check if the cookie->process(pid) already exists, and if not,
 * or if the cookie maps to a different process, add/update a
 * mapping from cookie to process(pid).
 */
static inline __attribute__((always_inline)) bool
update_socketmap(u64 *cookie, u32 pid)
{
	struct execve_map_value *value;
	struct socketmap_value *process;
	int zero = 0;

	if (!pid || !cookie || !*cookie)
		return false;

	process = lookup_socketmap(cookie);
	if (!process || process->key.pid != pid) {
		value = execve_map_get_noinit(pid);
		if (!value)
			return false;
		if (!process) {
			process = (struct socketmap_value *)map_lookup_elem(&tg_socket_map_heap, &zero);
			if (!process)
				return false;
			process->key.pid = value->key.pid;
			process->key.ktime = value->key.ktime;
			process->create_time = ktime_get_ns();
			process->version = udp_cookie_inc_version();
			add_socketmap(cookie, process, true);
		} else {
			process->key.pid = value->key.pid;
			process->key.ktime = value->key.ktime;
			process->create_time = ktime_get_ns();
			process->version = udp_cookie_inc_version();
		}
	}
	return true;
}

#endif
