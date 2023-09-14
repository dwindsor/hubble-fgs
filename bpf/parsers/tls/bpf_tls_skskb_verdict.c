#include "vmlinux.h"
#include "api.h"

#define SK_SKB

#include "iso_msg_types.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "tls_parser.h"
#include "ingress.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_skb/stream_verdict/fgs_tls"), used)) int
bpf_tls_skskb_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ip tuple = { 0 };
	u64 cookie_val = (u64)skb->sk;

	skskb_tls_tuple(skb, &tuple);
	bpf_parse_ingress_skb(skb, &tuple, 0, cookie_val);
	return SK_PASS;
}
