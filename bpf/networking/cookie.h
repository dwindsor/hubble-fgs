#ifndef __COOKIE_H_
#define __COOKIE_H_

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
