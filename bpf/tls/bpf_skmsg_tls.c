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

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

__attribute__((section(("sk_msg/tls")), used))
int bpf_sk_msg_tls(struct sk_msg_md *skmsg)
{
	struct msg_tls_event event = {0};

	event.common.op = MSG_OP_TLS;
	event.clienthello.type = 0;
	bpf_parse_tls(skmsg, (void *)(long)skmsg->data, 0, &event.clienthello);
	if (event.clienthello.type == TLS_TYPE_HANDSHAKE) {
		int err, zero = 0, *cntr;

		event.tuple.daddr = skmsg->remote_ip4;
		event.tuple.saddr = skmsg->local_ip4;
		event.tuple.dport = skmsg->remote_port;
		event.tuple.sport = skmsg->local_port;

		err = map_update_elem(&tls_map, &event.tuple, &event.clienthello, 0);
		if (!err && (cntr = map_lookup_elem(&tls_map_stats, &zero)))
			*cntr = *cntr + 1;
	}
	return SK_PASS;
}
