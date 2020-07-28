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
#include "parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

__attribute__((section(("tc/egress_tcp")), used))
int event_tc_egress_tcp(struct __sk_buff *skb)
{
	struct msg_tls_event event = {0};
	struct tcphdr *tcp;
	void *payload;
	int off = 0;

	tcp = skb_tls_key(skb, &off, &event.tuple);
	if (!tcp)
		return SK_PASS;
	payload = skb_tcp_payload(skb, tcp, &off);
	if (!payload)
		return SK_PASS;
	event.common.op = MSG_OP_TLS;
	event.clienthello.type = 0;
	bpf_parse_tls(skb, payload, off, &event.clienthello);
	if (is_expected_tls_client_hello(&event.clienthello))
		map_update_elem(&tls_map, &event.tuple, &event.clienthello, 0);
	return SK_PASS;
}
