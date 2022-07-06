#ifndef __COOKIE_H_
#define __COOKIE_H_

#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"

struct socketmap_value {
	struct msg_execve_key key;
	__u32 zero_window;
	__u32 socket_flags;
	__u64 last_time;
	__u64 sent;
	__u64 received;
};

struct bpf_map_def __attribute__((section("maps"), used))
socket_cookie_to_proc_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct socketmap_value),
	.max_entries = 32768,
};

struct bpf_map_def __attribute__((section("maps"), used)) socket_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct socketmap_value),
	.max_entries = 32768,
};

struct bpf_map_def __attribute__((section("maps"), used)) socket_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(__s64),
	.max_entries = 1,
};

// get socket cookie helper
static inline __attribute__((always_inline)) __u64 get_cookie(struct sock *sk)
{
	__u64 cookie = 0;
	probe_read(&cookie, sizeof(cookie), _(&(sk->__sk_common.skc_cookie)));
	return cookie;
}

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
write_cookie_from_sk(u64 *cookie, struct sock *sk, bool lazy)
{
	if (lazy) {
		write_cookie(cookie, (u64)sk);
	} else {
		*cookie = get_cookie(sk);
	}
}

static inline __attribute__((always_inline)) void
add_socketmap(struct msg_tls_ipv4 *tuple, struct socketmap_value *v)
{
	int err = map_update_elem(&socket_map, tuple, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&socket_map_stats, &zero)))
		*cntr = *cntr + 1;
}

static inline __attribute__((always_inline)) void
del_socketmap(struct msg_tls_ipv4 *tuple)
{
	int err = map_delete_elem(&socket_map, tuple);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&socket_map_stats, &zero)))
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline)) struct socketmap_value *
lookup_socketmap(struct msg_tls_ipv4 *tuple)
{
	return map_lookup_elem(&socket_map, tuple);
}

/* Check if the cookie->process(pid) already exists, and if not,
 * or if the cookie maps to a different process, add/update a
 * mapping from cookie to process(pid).
 */
static inline __attribute__((always_inline)) void
update_cookie_proc_map(u64 *cookie, u32 pid)
{
	struct execve_map_value *value;
	struct socketmap_value *process;

	if (!pid || !cookie || !*cookie)
		return;

	process = map_lookup_elem(&socket_cookie_to_proc_map, cookie);
	if (!process || process->key.pid != pid) {
		value = execve_map_get_noinit(pid);
		if (!value)
			return;
		if (!process) {
			struct socketmap_value s = { 0 };
			s.key.pid = value->key.pid;
			s.key.ktime = value->key.ktime;
			map_update_elem(&socket_cookie_to_proc_map, cookie, &s,
					0);
		} else {
			process->key.pid = value->key.pid;
			process->key.ktime = value->key.ktime;
			process->last_time = 0;
			process->received = 0;
			process->sent = 0;
			process->socket_flags = 0;
			process->zero_window = 0;
		}
	}
}

#endif
