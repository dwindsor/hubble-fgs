#ifndef __COOKIE_H_
#define __COOKIE_H_

#include "bpf_udp.h"

#ifndef SOCK_CTX
// get socket cookie helper
__u64 get_cookie(struct sock *skp) {
	__u64 cookie = 0;
	probe_read(&cookie, sizeof(cookie), _(&(skp->__sk_common.skc_cookie)));
	return cookie;
}
#endif

struct bpf_map_def __attribute__((section("maps"), used)) socket_cookie_to_proc_map = {
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
static inline __attribute__((always_inline))
void write_cookie(struct udp_info_key *key, u64 value)
{
	asm volatile(
		"*(u64 *)%[cookie] = %[value];\n"
	: [cookie] "+m"(key->cookie)
	: [value] "r"(value):);
}
