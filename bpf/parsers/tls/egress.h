// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef egress_h_INCLUDED
#define egress_h_INCLUDED

#include "iso_msg_types.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_sockops.h"
#include "tls_map.h"
#include "tls_parser.h"
#include "../../networking/bpf_cookie.h"
#include "../../networking/l3/tcp/bpf_tcp_info.h"

/* HTTP used for KTLS handlers */
// #include "../http/http_parser.h"

static inline __attribute__((always_inline)) void
egress_post_event(ctx_md *ctx, __u64 socket_cookie, __u64 socket_version,
		  struct msg_tls_event *post)
{
	post->socket_cookie = socket_cookie;
	post->socket_version = socket_version;
	post->common.op = ISO_MSG_OP_TLS;
	post->common.size = sizeof(struct msg_tls_event);
	post->common.ktime = ktime_get_ns();
	perf_event_output_metric(ctx, ISO_MSG_OP_TLS, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				 sizeof(struct msg_tls_event));
}

#ifdef SK_MSG
static inline __attribute__((always_inline)) void
bpf_parse_tls_egress(ctx_md *ctx, u64 *cookie)
#else
static inline __attribute__((always_inline)) void
bpf_parse_tls_egress(ctx_md *ctx, u64 *cookie, int payload_off)
#endif
{
	struct tcpsocketmap_value *socket;
	struct msg_tls_event *event;
	struct msg_tls *clienthello;
	struct msg_tls *state;
	struct bottle *bottle;
	int zero = 0;
#ifdef SK_MSG
	int payload_off = 0;
#endif

	socket = lookup_tcpsocketmap(cookie);
	if (!socket)
		return;

	state = map_lookup_elem(&tg_tls_map, cookie);
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

		egress_post_event(ctx, *cookie, socket->version, event);

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
