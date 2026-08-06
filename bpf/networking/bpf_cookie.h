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
#include "bpf_ktime.h"

struct socketmap_value {
	struct msg_execve_key key;
	__u64 create_time;
	__u64 version;
	__u8 protocol;
	__u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct socketmap_value);
	__uint(max_entries, 1); // will be resized by user space
} tg_l3_sk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_l3_sk_stats SEC(".maps");

/* Store the latest cookie version number. Each socket receives a
 * new global version number, unique to each socket.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} tg_l3_sk_ver SEC(".maps");

/* Generate a new socket cookie version number.
 * We track sockets by the address of their struct sock, as these are unique to the
 * socket and are close to the skb. Due to the same memory locations being reused when
 * socket structs are recycled, it is possible for user space to be confused between
 * two different sockets with the same cookie (address). To help, each new socket is
 * allocated a new socket cookie version number and this is stored in the socket map
 * value.
 *
 * As there could be many cores creating sockets at the same time, the function uses
 * an atomic instruction to increment the counter. Unfortunately, as the right atomic
 * functions are not available on older kernels, there is a race condition where two
 * cores could update the version value (one after the other), and both read the
 * second value that was written.
 *
 * In this situation, we can guarantee that the two sockets being allocated
 * simultaneously will have different socket cookies (different addresses), so they
 * will never need to be disambiguated by user space. In other words, the combination
 * of socket cookie and version will still be unique, even if two sockets allocated
 * simulataneously receive the same version number.
 *
 * We opted for a sequential count over a random value to aid debugging.
 */
static inline __attribute__((always_inline)) u64
cookie_inc_version()
{
	u64 *version;
	u32 zero = 0;

	version = (u64 *)map_lookup_elem(&tg_l3_sk_ver, &zero);
	if (!version)
		return 0;
	__sync_fetch_and_add(version, 1);
	return *version;
}

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
add_socketmap(u64 *cookie, struct socketmap_value *v, struct msg_ip_tuple *tuple, bool update_tuple_map)
{
	struct socketmap_value *existing = (struct socketmap_value *)map_lookup_elem(&tg_l3_sk, cookie);
	int zero = 0;
	__s64 *cntr;
	int err;

	if (existing && existing->key.pid == v->key.pid && existing->key.ktime == v->key.ktime && existing->version == v->version)
		return;

	err = map_update_elem(&tg_l3_sk, cookie, v, 0);
	if (!err) {
		if (!existing && (cntr = (__s64 *)map_lookup_elem(&tg_l3_sk_stats, &zero)))
			*cntr = *cntr + 1;
		if (update_tuple_map)
			add_socket_tuple_map(tuple, cookie);
	}
}

static inline __attribute__((always_inline)) void
del_socketmap(u64 *cookie)
{
	int err = map_delete_elem(&tg_l3_sk, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_l3_sk_stats, &zero)))
			*cntr = *cntr - 1;
		del_socket_tuple_map(cookie);
	}
}

static inline __attribute__((always_inline)) struct socketmap_value *
lookup_socketmap(u64 *cookie)
{
	return (struct socketmap_value *)map_lookup_elem(&tg_l3_sk, cookie);
}

#endif
