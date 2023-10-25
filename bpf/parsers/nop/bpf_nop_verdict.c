#include "vmlinux.h"
#include "api.h"

__attribute__((section("sk_skb/stream_verdict/fgsnop"), used)) int
tg_skskb_http_verdict(struct __sk_buff *skb)
{
	return SK_PASS;
}
