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

__attribute__((section(("sk_msg/tls")), used))
int bpf_sk_msg_tls(struct sk_msg_md *skmsg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_tls clienthello = {0};
	void *payload = skmsg->data;

	skb_tls_key(skmsg, &tuple);

	clienthello.type = 0;
	bpf_parse_tls(skmsg, payload, 0, &clienthello);
	if (is_expected_tls_client_hello(&clienthello))
		add_tlsmap(&tuple, &clienthello);

	return SK_PASS;
}
