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

__attribute__((section(("sk_skb_nop_parser/fgsnop")), used)) int
bpf_skskb_nop_parser(struct __sk_buff *skb)
{
	return skb->len;
}
