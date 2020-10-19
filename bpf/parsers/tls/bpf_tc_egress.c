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
#include "tls_map.h"
#include "parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("tc/egress_tcp")), used))
int event_tc_egress_tcp(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_tls clienthello = {0};
	struct tcphdr *tcp;
	void *payload;
	int off = 0;

	tcp = skb_tls_key(skb, &off, &tuple);
	if (!tcp)
		return TC_ACT_UNSPEC;
	payload = skb_tcp_payload(skb, tcp, &off);
	if (!payload)
		return TC_ACT_UNSPEC;
	clienthello.type = 0;
	bpf_parse_tls(skb, payload, off, &clienthello);
	if (is_expected_tls_client_hello(&clienthello))
		add_tlsmap(&tuple, &clienthello);
	return TC_ACT_UNSPEC;
}
