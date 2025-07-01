// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "parsers/tls/tls_map.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "lib/netns.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"
#include "parsers/http/http.h"
#include "parsers/bottle.h"
#include "../bpf_network_event_config.h"
#include "bpf_tcp_state.h"

static inline __attribute__((always_inline)) int
__event_tcp_close(void *ctx, struct sock *skp, int state)
{
	struct event_disable_config *event_cfg;
	struct msg_ip_with_stats_event *val;
	struct tcpsocketmap_value *socket;
	unsigned char old_state;
	u32 zero = 0;
	size_t size;
	u64 cookie;

	if (state != TCP_CLOSE)
		return 0;

	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	/* Get the state that we are transitioning from */
	probe_read_kernel(&old_state, sizeof(old_state),
			  (const void *)_(&(skp->__sk_common.skc_state)));

	socket = lookup_tcpsocketmap(&cookie);
	if (!socket) {
		// Don't report an error here if the TCP socket isn't yet active.
		if (tcp_active(old_state))
			emit_ip_error_event(ctx, 0, &cookie, false, 0, 0, 0, IP_ERROR_TCP_CLOSE_NO_SOCKET);
		return 0;
	}

	/* We don't need to account further if the socket has already been closed. */
	if (socket->closed)
		return 0;

	val = (struct msg_ip_with_stats_event *)map_lookup_elem(&tcp_close_event_map,
								&zero);
	if (!val)
		return 0;

	*val = (struct msg_ip_with_stats_event){
		.common.size = sizeof(struct msg_ip_with_stats_event),
		.common.ktime = ktime_get_ns(),

		.socket_cookie = cookie,
		.version = socket->version,
	};

	val->common.op = ISO_MSG_OP_TCPCLOSE;
	val->key.pid = socket->key.pid;
	val->key.ktime = socket->key.ktime;
	val->create_time = socket->stats.create_time;
	val->close_time = ktime_get_ns();
	val->socket_flags = socket->socket_flags;
	if (old_state == TCP_SYN_SENT)
		val->socket_flags |= SOCKFLAGS_CONNECT_FAILED;
	val->tuple = socket->tuple;

	get_socket_stats(skp, socket, &val->stats);
	socket->closed = 1;

	event_cfg = (struct event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	size = sizeof(struct msg_ip_with_stats_event);
	if (!event_cfg->disableClose) {
		perf_event_output_metric(ctx, ISO_MSG_OP_TCPCLOSE, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					 size);
	}

	if (!socket->tuple.ipv6) {
		del_tlsmap(&cookie);
		map_delete_elem(&tg_http_map, &cookie);
		bottle_drop(&cookie);
	}

	return 1;
}
