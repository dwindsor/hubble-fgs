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
#define TLS_PORT 443

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"

#include "tls/bpf_skmsg_tls.h"

__attribute__((section(("sk_msg/fgs")), used))
int bpf_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	return bpf_sk_msg_tls(skmsg);
}
