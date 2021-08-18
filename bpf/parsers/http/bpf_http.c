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
#include "../bpf_sockops.h"
#include "../parser.h"
#include "http.h"
#include "http_parser.h"

__attribute__((section(("sk_msg/fgs")), used))
int bpf_http_sk_msg_fgs(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};

	msg_tls_key(msg, &tuple);
	return http_do_parser(msg, &tuple);
}

char _license[] __attribute__((section(("license")), used)) = "GPL";
