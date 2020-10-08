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

#define SK_MSG

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"
#include "parser.h"
#include "tls_map.h"

__attribute__((section(("sk_skb_verdict/tls")), used))
int bpf_skskb_verdict_tls(struct __sk_buff *skb)
{
	return SK_PASS;
}
