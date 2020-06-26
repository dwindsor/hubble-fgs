/* Structure representing an L7 sock */
struct sock_key {
	struct {
		__u32		sip4;
		__u32		pad1;
		__u32		pad2;
		__u32		pad3;
	};
	struct {
		__u32		dip4;
		__u32		pad4;
		__u32		pad5;
		__u32		pad6;
	};
	__u8 family;
	__u8 pad7;
	__u16 pad8;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

#define SOCKOPS_MAP_SIZE 65535
#define AF_INET 2

#define BPF_NOEXIST 1

# define bpf_ntohs(x)		__builtin_bswap16(x)
# define bpf_htons(x)		__builtin_bswap16(x)
# define bpf_ntohl(x)		__builtin_bswap32(x)
# define bpf_htonl(x)		__builtin_bswap32(x)

#define _(P) (__builtin_preserve_access_index(P))

#include "bpf_core_read.h"

#ifndef __READ_ONCE
# define __READ_ONCE(x)		(*(volatile typeof(x) *)&x)
#endif
#ifndef __WRITE_ONCE
# define __WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)
#endif

#ifndef READ_ONCE
# define READ_ONCE(x)		\
	({ typeof(x) __val; __val = __READ_ONCE(x); compiler_barrier(); __val; })
#endif
#ifndef WRITE_ONCE
# define WRITE_ONCE(x, v)	\
	({ typeof(x) __val = (v); __WRITE_ONCE(x, __val); compiler_barrier(); __val; })
#endif

struct bpf_map_def __attribute__((section("maps"), used)) fgs_sock_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries	= SOCKOPS_MAP_SIZE,
};

__attribute__((unused))
static void sk_extract4_key(struct bpf_sock_ops *ops,
					    struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = AF_INET;

	key->sport = (bpf_ntohl(ops->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated. */
	key->dport = READ_ONCE(ops->remote_port) >> 16;
}

__attribute__((unused))
static void sk_msg_extract4_key(struct sk_msg_md *msg,
				struct sock_key *key)
{
	key->dip4 = msg->remote_ip4;
	key->sip4 = msg->local_ip4;
	key->family = AF_INET;

	key->sport = (bpf_ntohl(msg->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated. */
	key->dport = READ_ONCE(msg->remote_port) >> 16;
}
