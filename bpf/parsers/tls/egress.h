#ifndef egress_h_INCLUDED
#define egress_h_INCLUDED

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "tls_parser.h"

/* HTTP used for KTLS handlers */
#include "../http/http_parser.h"

static inline __attribute__((always_inline)) void
egress_post_event(ctx_md *ctx, struct msg_tls_ip *tuple,
		  struct msg_tls_event *post)
{
	post->tuple = *tuple;
	post->common.op = ISO_MSG_OP_TLS;
	post->common.size = sizeof(struct msg_tls_event);
	post->common.ktime = ktime_get_ns();
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, post,
			  sizeof(struct msg_tls_event));
}

#ifdef SK_MSG
static inline __attribute__((always_inline)) void
bpf_parse_tls_egress(ctx_md *ctx, u64 *cookie)
#else
static inline __attribute__((always_inline)) void
bpf_parse_tls_egress(ctx_md *ctx, struct iphdr *ip, bool ipv6,
		     struct tcphdr *tcp, u64 *cookie, int payload_off)
#endif
{
	struct msg_tls_ip tuple = { 0 };
	struct msg_tls_event *event;
	struct msg_tls *clienthello;
	struct msg_tls *state;
	struct bottle *bottle;
	int zero = 0;
#ifdef SK_MSG
	int payload_off = 0;
#endif

#ifdef SK_MSG
	msg_tls_tuple(ctx, &tuple);
#else
	if (!ipv6) {
		tuple.daddr[0] = ip->daddr;
		tuple.saddr[0] = ip->saddr;
		tuple.ipv6 = 0;
	} else {
		struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
		u64 *addr = (u64 *)&ip6->daddr;
		tuple.daddr[0] = addr[0];
		tuple.daddr[1] = addr[1];
		addr = (u64 *)&ip6->saddr;
		tuple.saddr[0] = addr[0];
		tuple.saddr[1] = addr[1];
		tuple.ipv6 = 1;
	}
	tuple.dport = tcp->dest;
	tuple.sport = tcp->source;

	/* Hooks read sport in network order, but rest of stack
	 * expects host order for sport so we do conversion here.
	 */
	tuple.sport = bpf_ntohs(tuple.sport);
	tuple.uid = get_socket_cookie(ctx);
#endif

	state = map_lookup_elem(&tls_map, cookie);
	if (state) {
#ifdef SK_MSG

		/* An event here indicates we have TLS state associated
		 * with this socket and/or we have aborted parsing on the
		 * TLS socket. If it is a KTLS socket we can also pass to
		 * HTTP parser for handling
		 */
		/* Currently disabled due to verifier not liking the complexity
		 * it brings.
		 */
		/*
		if (state->version == TLS_HTTP_VERSION)
			http_do_parser(ctx, &tuple);
		*/
#endif
		return;
	}

	bottle = bottle_fill(ctx, cookie, payload_off);
	if (!bottle) {
		tls_inc_bottle_fill_failed();
		return;
	}

	event = map_lookup_elem(&tls_heap, &zero);
	if (!event)
		return;

	memset(event, 0, sizeof(*event));
	clienthello = &event->clienthello;

	switch (bpf_parse_tls(bottle, clienthello)) {
	case TLS_PARSE_OUT_OF_DATA:
		/* Parser ran out of data. Try again later with more data. */
		tls_inc_egress_out_of_data();
		return;

	case TLS_PARSE_ERROR:
		tls_inc_egress_parse_error();

		/* Post the event to user-space, if port filtering is enabled
                 * and we're not expecting to see non-TLS traffic. */
		if (tls_filter_is_populated())
			egress_post_event(ctx, &tuple, event);

		/* Add an entry to stop parsing further packets */
		tls_mark_complete(clienthello);
		break;

	default:
		tls_inc_egress_ok();
		break;
	}
	bottle_drop(cookie);
	add_tlsmap(cookie, clienthello);
}

#endif // egress_h_INCLUDED
