#include "vmlinux.h"
#include "api.h"

__attribute__((section(("sk_skb_nop_verdict/fgsnop")), used))
int bpf_skskb_http_verdict(struct __sk_buff *skb)
{
	return SK_PASS;
}
