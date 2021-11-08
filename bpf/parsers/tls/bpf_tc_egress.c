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

__attribute__((section(("classifier/egress_tcp")), used))
int event_tc_egress_tcp(struct __sk_buff *skb)
{
	struct msg_tls clienthello = {0};
	struct msg_tls_ipv4 tuple = {0};
	struct skb_bottle *bottle;
	struct tcphdr *tcp;
	int off = 0;

	tcp = skb_tls_key(skb, &off, &tuple);
	if (!tcp)
		return TC_ACT_UNSPEC;

	if (!skb_tcp_payload(skb, tcp, &off)) {
		return TC_ACT_UNSPEC;
	}

	if (map_lookup_elem(&tls_map, &tuple) != 0)
		/* Already parsed, or parsing failed and should ignore. */
		return TC_ACT_UNSPEC;

	bottle = skb_bottle_fill(skb, &tuple, off);
	if (!bottle)
		return TC_ACT_UNSPEC;

	switch (bpf_parse_tls(bottle, &clienthello)) {
	case TLS_PARSE_BAD_DATA:
		/* Parsing failed. Add an entry to stop parsing further packets. */
		tls_mark_complete(&clienthello);
		map_delete_elem(&skb_bottles, &tuple);
		add_tlsmap(&tuple, &clienthello);
		break;

	case TLS_PARSE_OUT_OF_DATA:
		/* Parser ran out of data. Try again later with more data. */
		break;

	default:
		/* Success! Add the tls entry to start parsing ingress data. */
		map_delete_elem(&skb_bottles, &tuple);
		add_tlsmap(&tuple, &clienthello);
		break;
	}

	return TC_ACT_UNSPEC;
}
