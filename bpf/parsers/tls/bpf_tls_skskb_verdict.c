#include "vmlinux.h"
#include "api.h"

#define SK_SKB

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "tls_parser.h"
#include "ingress.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_skb/stream_verdict/fgs_tls"), used)) int
bpf_tls_skskb_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = { 0 };

	skskb_tls_key(skb, &key);
	bpf_parse_ingress_skb(skb, &key, 0);
	return SK_PASS;
}
