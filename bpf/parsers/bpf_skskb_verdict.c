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

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"
#include "tls/tls_map.h"
#include "tls/parser.h"
#include "tls/ingress.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("sk_skb_verdict/fgs")), used))
int bpf_skskb_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};

	skskb_tls_key(skb, &key);
	bpf_parse_ingress_skb(skb, &key, 0);
	return SK_PASS;
}
