#ifndef egress_h_INCLUDED
#define egress_h_INCLUDED

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "parser.h"

static inline __attribute__((always_inline))
void bpf_parse_tls_egress(ctx_md *ctx)
{
	struct msg_tls clienthello = {0};
	struct msg_tls_ipv4 tuple = {0};
	struct bottle *bottle;
	int off = 0;

#ifdef SK_MSG
	skmsg_tls_key(ctx, &tuple);
#else
	struct tcphdr *tcp;
	tcp = skb_tls_key(ctx, &off, &tuple);
	if (!tcp)
		return;

	if (!skb_tcp_payload(ctx, tcp, &off)) {
		return;
	}
#endif

	if (map_lookup_elem(&tls_map, &tuple) != 0)
		/* Already parsed, or parsing failed and should ignore. */
		return;

	bottle = bottle_fill(ctx, &tuple, off);
	if (!bottle)
		return;

	switch (bpf_parse_tls(bottle, &clienthello)) {
	case TLS_PARSE_BAD_DATA:
		/* Parsing failed. Add an entry to stop parsing further packets. */
		tls_mark_complete(&clienthello);
		bottle_drop(&tuple);
		add_tlsmap(&tuple, &clienthello);
		break;

	case TLS_PARSE_OUT_OF_DATA:
		/* Parser ran out of data. Try again later with more data. */
		break;

	default:
		/* Success! Add the tls entry to start parsing ingress data. */
		bottle_drop(&tuple);
		add_tlsmap(&tuple, &clienthello);
		break;
	}
}

#endif // egress_h_INCLUDED

