#include "vmlinux.h"
#include "api.h"

__attribute__((section("sk_skb/stream_parser/fgs_tls"), used)) int
bpf_tls_skskb_parser_fgs(struct __sk_buff *skb)
{
	return skb->len;
}
