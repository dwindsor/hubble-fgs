#ifndef __COOKIE_H_
#define __COOKIE_H_

#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"

struct socketmap_value {
	struct msg_execve_key key;
	__u64 create_time;
	__u32 zero_window;
	__u32 socket_flags;
	__u64 last_time;
	__u64 sent;
	__u64 received;
	__u64 rtt_buckets[8];
	__u64 latency_buckets[8];
	__u8 ack_finack;
	__u8 pad[7];
	__u64 rtt_sum;
	__u64 latency_sum;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct socketmap_value);
	__uint(max_entries, 32768);
} tg_socket_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct msg_tls_ip);
	__type(value, struct socketmap_value);
	__uint(max_entries, 32768);
} tg_tls_socket_map SEC(".maps");

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
	probe_read(&cookie, sizeof(cookie), _(&(sk->__sk_common.skc_cookie)));
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

static inline __attribute__((always_inline)) void
add_socketmap(u64 *cookie, struct msg_tls_ip *t, struct socketmap_value *v)
{
	int err = map_update_elem(&tg_socket_map, cookie, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = (__s64 *)map_lookup_elem(&tg_socket_map_stats, &zero))) {
		*cntr = *cntr + 1;
		if (t)
			map_update_elem(&tg_tls_socket_map, t, v, 0);
	}
}

static inline __attribute__((always_inline)) void
del_socketmap(u64 *cookie, struct msg_tls_ip *t)
{
	int err = map_delete_elem(&tg_socket_map, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = (__s64 *)map_lookup_elem(&tg_socket_map_stats, &zero))) {
		*cntr = *cntr - 1;
	}
	if (t)
		map_delete_elem(&tg_tls_socket_map, t);
}

static inline __attribute__((always_inline)) struct socketmap_value *
lookup_socketmap(u64 *cookie)
{
	return (struct socketmap_value *)map_lookup_elem(&tg_socket_map, cookie);
}

static inline __attribute__((always_inline)) struct socketmap_value *
lookup_tls_socketmap(struct msg_tls_ip *t)
{
	return (struct socketmap_value *)map_lookup_elem(&tg_tls_socket_map, t);
}

/* Check if the cookie->process(pid) already exists, and if not,
 * or if the cookie maps to a different process, add/update a
 * mapping from cookie to process(pid).
 */
static inline __attribute__((always_inline)) bool
update_socketmap(u64 *cookie, struct msg_tls_ip *t, u32 pid)
{
	struct execve_map_value *value;
	struct socketmap_value *process;
	int zero = 0;

	if (!pid || !cookie || !*cookie)
		return false;

	process = lookup_socketmap(cookie);
	if (!process || process->key.pid != pid) {
		int i;
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
			process->last_time = 0;
			process->received = 0;
			process->sent = 0;
			process->socket_flags = 0;
			process->zero_window = 0;
			process->ack_finack = 0;
#pragma unroll
			for (i = 0; i < 8; i++) {
				process->rtt_buckets[i] = 0;
				process->latency_buckets[i] = 0;
			}
			process->rtt_sum = 0;
			process->latency_sum = 0;
			add_socketmap(cookie, t, process);
		} else {
			process->key.pid = value->key.pid;
			process->key.ktime = value->key.ktime;
			process->create_time = ktime_get_ns();
			process->last_time = 0;
			process->received = 0;
			process->sent = 0;
			process->socket_flags = 0;
			process->zero_window = 0;
			process->ack_finack = 0;
#pragma unroll
			for (i = 0; i < 8; i++) {
				process->rtt_buckets[i] = 0;
				process->latency_buckets[i] = 0;
			}
			process->rtt_sum = 0;
			process->latency_sum = 0;
		}
	}
	return true;
}

#endif
