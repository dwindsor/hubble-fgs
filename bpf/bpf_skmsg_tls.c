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

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"
#include "tls/parser.h"

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("sk_msg/tls")), used))
int bpf_sk_msg_tls(struct sk_msg_md *skmsg)
{
	struct msg_tls_event event = {0};

	event.common.op = MSG_OP_TLS;
	event.tls.type = 0;
	bpf_parse_tls(skmsg, &event.tls);
	if (event.tls.type == TLS_TYPE_HELLO) {
		event.tuple.daddr = skmsg->remote_ip4;
		event.tuple.saddr = skmsg->local_ip4;
		event.tuple.dport = skmsg->remote_port;
		event.tuple.sport = skmsg->local_port;
		map_update_elem(&tls_map, &event.tuple, &event.tls, 0);
	}
	return SK_PASS;
}
