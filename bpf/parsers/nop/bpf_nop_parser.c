#include "vmlinux.h"
#include "api.h"

__attribute__((section("sk_skb/stream_parser/fgsnop"), used)) int
bpf_skskb_nop_parser(struct __sk_buff *skb)
{
	return skb->len;
}
