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
	key->remaining = HTTP_RECV;
	// tbd, cover sk null case for ealier kernels.
}

__attribute__((section(("sk_skb_http_verdict/fgshttp")), used))
int bpf_skskb_http_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};

	skskb_http_key(skb, &key);
	return http_do_parser(skb, &key);
}

__attribute__((section(("sk_skb/0")), used))
int bpf_skskb_http_response(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct msg_http *http;

	skskb_http_key(skb, &key);
	http = get_http_context(&key);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_response(skb, http);
	http->state = http_done;
	if (http->state == http_done) {
		post_http_event(skb, &key, http);
		http_reset_state(http);
	}
	return SK_PASS;
}

__attribute__((section(("sk_skb/1")), used))
int bpf_skskb_http_request(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct msg_http *http;

	skskb_http_key(skb, &key);
	http = get_http_context(&key);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_request(skb, http);
	http->state = http_done;
	if (http->state == http_done) {
		post_http_event(skb, &key, http);
		http_reset_state(http);
	}
	return SK_PASS;
}
