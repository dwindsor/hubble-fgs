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

#include "tls/bpf_skskb_verdict_tls.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("sk_skb_verdict/fgs")), used))
int bpf_skskb_verdict(struct __sk_buff *skb)
{
	return bpf_skskb_verdict_tls(skb);
}
