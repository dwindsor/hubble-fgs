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

#define SK_SKB

#include "http_parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

static inline __attribute__((always_inline))
void skskb_http_key(struct __sk_buff *skb, struct msg_tls_ipv4 *key) {
	struct bpf_sock *sk;

	key->daddr = skb->remote_ip4;
	key->saddr = skb->local_ip4;

	sk = skb->sk;
	if (sk) {
		key->dport = skb->sk->dst_port;
		key->sport = skb->sk->src_port;
	}
	// tbd, cover sk null case for ealier kernels.
}

__attribute__((section(("sk_skb_http_verdict/fgshttp")), used))
int bpf_skskb_http_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};

	skskb_http_key(skb, &key);
	return http_do_parser(skb, &key);
}
