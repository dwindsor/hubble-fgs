#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_sockops.h"
#include "./tls/tls_map.h"

/* Hard coding policy until we have policy map in place. */
#define TLS_PORT 443
#define SK_MSG

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};

	sk_extract4_key(skops, &key);
	if (tls_filter(&key) == TLS_TRACK) {
		sock_hash_update(skops, &tls_sock_map, &key, BPF_NOEXIST);
	}
}

__section("sockops/fgs_sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == AF_INET)
			bpf_sock_ops_ipv4(skops);
		break;
	default:
		break;
	}

	return 0;
}

char _license[] __attribute__((section(("license")), used)) = "GPL";
