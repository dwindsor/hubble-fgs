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

#include "egress.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("sk_msg/fgs_tls")), used))
int bpf_tls_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	bpf_parse_tls_egress(skmsg);
	return SK_PASS;
}
