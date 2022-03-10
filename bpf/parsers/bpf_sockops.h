#ifndef __BPF_SOCKOPS_H
#define __BPF_SOCKOPS_H
/* Structure representing an L7 sock */
struct sock_key {
	__u64 cookie;
	__u32 dport;
	__u32 sport;
} __attribute__((packed));

#define SOCKOPS_TLS_MAP_SIZE 65535
#define SOCKOPS_HTTP_MAP_SIZE 2000
#define SOCKOPS_NOP_MAP_SIZE 32

#define AF_INET 2

#define BPF_NOEXIST 1

# define bpf_ntohs(x)		__builtin_bswap16(x)
# define bpf_htons(x)		__builtin_bswap16(x)
# define bpf_ntohl(x)		__builtin_bswap32(x)
# define bpf_htonl(x)		__builtin_bswap32(x)

#define _(P) (__builtin_preserve_access_index(P))

#include "bpf_core_read.h"
#include "../lib/bpf_helpers.h"

__attribute__((unused))
static void sk_extract4_key(struct bpf_sock_ops *ops,
			    struct sock_key *key)
{
	key->cookie = get_socket_cookie(ops);
	if (ops->sk) {
		key->dport = ops->sk->dst_port;
		key->sport = ops->sk->src_port;
	}
	/* We only use sockops on 5.4+ kernels in these cases
	 * the ops->sk is set so we can skip else case.
	 */
}

#endif //__BPF_SOCKOPS_H
