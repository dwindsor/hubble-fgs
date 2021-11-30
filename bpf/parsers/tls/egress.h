#ifndef egress_h_INCLUDED
#define egress_h_INCLUDED

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "tls_parser.h"

static inline __attribute__((always_inline))
void egress_post_event(ctx_md *ctx, struct msg_tls_ipv4 *key, struct msg_tls *clienthello)
{
       struct msg_tls_event *post;
       int zero = 0;

       post = map_lookup_elem(&tls_heap, &zero);
       if (!post)
               return;

       post->clienthello = *clienthello;
       memset(&post->serverhello, 0, sizeof(post->serverhello));
       post->tuple = *key;
       post->common.op = MSG_OP_TLS;
       post->common.size = sizeof(struct msg_tls_event);
       post->common.ktime = ktime_get_ns();
       perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, post,
                         sizeof(struct msg_tls_event));
}

static inline __attribute__((always_inline))
void bpf_parse_tls_egress(ctx_md *ctx)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_tls *clienthello;
	struct bottle *bottle;
	int off = 0;
	int zero = 0;

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
	/* TC hooks read sport in network order, but rest of stack
	 * expects host order for sport so we do conversion here.
	 */
	tuple.sport = bpf_ntohs(tuple.sport);
#endif

	if (map_lookup_elem(&tls_map, &tuple) != 0)
		/* Already parsed, or parsing failed and should ignore. */
		return;

	bottle = bottle_fill(ctx, &tuple, off);
	if (!bottle) {
		tls_inc_bottle_fill_failed();
		return;
	}

	clienthello = map_lookup_elem(&tls_heap, &zero);
	if (!clienthello)
		return;

	switch (bpf_parse_tls(bottle, clienthello)) {
	case TLS_PARSE_OUT_OF_DATA:
		/* Parser ran out of data. Try again later with more data. */
		tls_inc_egress_out_of_data();
		return;

	case TLS_PARSE_ERROR:
		/* Parsing failed, mark parsing as completed to stop further parsing. */
		tls_inc_egress_parse_error();
		tls_mark_complete(clienthello);

                /* Post the event to user-space */
                // TODO(JM): Commented out for now. Tests need adjusting.
                // egress_post_event(ctx, &tuple, clienthello);
		break;
	default:
		tls_inc_egress_ok();
		break;
	}
	bottle_drop(&tuple);
	add_tlsmap(&tuple, clienthello);
}

#endif // egress_h_INCLUDED

