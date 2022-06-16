#ifndef __COOKIE_H_
#define __COOKIE_H_

#include "bpf_udp.h"

// get socket cookie helper
static inline __attribute__((always_inline)) __u64 get_cookie(struct sock *sk)
{
	__u64 cookie = 0;
	probe_read(&cookie, sizeof(cookie), _(&(sk->__sk_common.skc_cookie)));
	return cookie;
}

struct bpf_map_def __attribute__((section("maps"), used))
socket_cookie_to_proc_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct execve_map_value),
	.max_entries = 32768,
};
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
write_cookie_from_sk(u64 *cookie, struct sock *sk, bool lazy)
{
	if (lazy) {
		write_cookie(cookie, (u64)sk);
	} else {
		*cookie = get_cookie(sk);
	}
}

/* Check if the cookie->process(pid) already exists, and if not,
 * or if the cookie maps to a different process, add/update a
 * mapping from cookie to process(pid).
 */
static inline __attribute__((always_inline)) void
update_cookie_proc_map(u64 *cookie, u32 pid)
{
	struct execve_map_value *value;
	struct execve_map_value *process;

	if (!pid || !cookie || !*cookie)
		return;

	process = map_lookup_elem(&socket_cookie_to_proc_map, cookie);
	if (!process || process->key.pid != pid) {
		value = execve_map_get(pid);
		if (value) {
			map_update_elem(&socket_cookie_to_proc_map, cookie,
					value, 0);
		}
	}
}
