// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//

#define PROCESS_TREE
#include "bpf_tcp_connect.h"
#include "bpf_tcp_state.h"
#include "bpf_tcp_listen.h"
#include "bpf_ktime.h"
#include "parsers/http/http_parser.h"
#include "parsers/bottle.h"
#include "config.h"

int skops_socket(u64 cookie, struct msg_ip_event *val, struct socketmap_value *socket)
{
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = tg_get_ktime();
	val->ret = 0;
	val->socket_cookie = cookie;
	val->socket_flags = 0;
	val->version = socket->version;
	val->key.pid = socket->key.pid;
	val->key.ktime = socket->key.ktime;
	val->create_time = socket->create_time;
	val->ps_version = 0; // not a UDP event; keep deterministic
	val->close_time = 0; // socket not closed yet on connect/listen

	return 0;
}

int skops_tcpsocket(u64 cookie, struct msg_ip_event *val, struct tcpsocketmap_value *socket)
{
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = tg_get_ktime();
	val->ret = 0;
	val->socket_cookie = cookie;
	val->version = socket->version;
	val->key.pid = socket->key.pid;
	val->key.ktime = socket->key.ktime;
	val->create_time = socket->stats.create_time;
	val->socket_flags = socket->socket_flags;
	val->ps_version = 0;
	// close path sets close_time = tg_get_ktime() afterward; zero here is
	// harmless and keeps the helper's output fully initialized.
	val->close_time = 0;

	return 0;
}

int skops_socket_with_stats(u64 cookie, struct msg_ip_with_stats_event *val, struct tcpsocketmap_value *socket)
{
	skops_tcpsocket(cookie, (struct msg_ip_event *)val, socket);
	val->common.size = sizeof(struct msg_ip_with_stats_event);
	return 0;
}

int skops_tuple(u64 cookie, struct msg_ip_event *val, struct bpf_sock_ops *skops)
{
	if (!val)
		return 0;

	val->tuple.sport = _(skops->local_port);
	probe_read_kernel(&val->tuple.dport, sizeof(val->tuple.dport),
			  _(&(((struct sock *)cookie)->__sk_common.skc_dport)));
	val->tuple.dport = bpf_ntohs(val->tuple.dport);

	if (_(skops->family) != AF_INET6) {
		val->tuple.ipv6 = false;
		val->tuple.saddr[0] = _(skops->local_ip4);
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[0] = _(skops->remote_ip4);
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
				  _(&(((struct sock *)cookie)->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
				  _(&(((struct sock *)cookie)->__sk_common.skc_v6_daddr)));
	}
	val->tuple.conn_id = 0;

	return 0;
}

int skops_tuple_with_stats(u64 cookie, struct msg_ip_with_stats_event *val, struct bpf_sock_ops *skops)
{
	return skops_tuple(cookie, (struct msg_ip_event *)val, skops);
}

int event_tcp_sockops_listen(struct bpf_sock_ops *skops)
{
	struct tcp_event_disable_config *event_cfg;
	struct socketmap_value *socket = 0;
	struct tcpsocketmap_value *v;
	struct msg_ip_event *val;
	struct cfg_value *l3cfg;
	u64 cookie, __cookie;
	u32 zero = 0;

	/* In TCP we use the struct sock address as the socket cookie.
	 * Verifier on 6.15 (maybe earlier) maintained that cookie was a sock-or-null and
	 * didn't want to pass it to the skops_tuple() function as a scalar. This
	 * construction converts the sock-or-null to a scalar. Note, probe_reading
	 * directly from the _(skops->sk) caused confusion so should be avoided.
	*/
	__cookie = (u64)_(skops->sk);
	probe_read_kernel(&cookie, sizeof(cookie), &__cookie);
	socket = lookup_socketmap(&cookie);
	if (!socket)
		return 0;

	// Set the protocol here because it probably wasn't specified at the time of
	// socket allocation.
	socket->protocol = IPPROTO_TCP;

	val = (struct msg_ip_event *)map_lookup_elem(&tg_h_event,
						     &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_LISTEN;
	skops_socket(cookie, val, socket);
	skops_tuple(cookie, val, skops);

	l3cfg = getl3cfg();
	if (!l3cfg)
		return 0;
	event_cfg = &l3cfg->tcp_disable;

	if (!event_cfg->disableListen) {
		perf_event_output_metric(skops, ISO_MSG_OP_LISTEN, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					 sizeof(struct msg_ip_event));
	}

	v = init_tcpsocketmap_value(&val->key, _(skops->family), SOCKFLAGS_TYPE_LISTEN, socket->create_time, socket->version, &val->tuple);
	if (!v)
		return 0;
	add_tcpsocketmap(&cookie, v, true);

	return 0;
}

int event_tcp_sockops_connect(struct bpf_sock_ops *skops)
{
	struct destination_endpoint_value *dest;
	struct socketmap_value *socket = 0;
	struct msg_ip_with_tnp_event *val;
	struct msg_execve_key *key;
	u64 cookie, __cookie;
	__u32 zero = 0;

	/* In TCP we use the struct sock address as the socket cookie.
	 * Verifier on 6.15 (maybe earlier) maintained that cookie was a sock-or-null and
	 * didn't want to pass it to the skops_tuple() function as a scalar. This
	 * construction converts the sock-or-null to a scalar. Note, probe_reading
	 * directly from the _(skops->sk) caused confusion so should be avoided.
	*/
	__cookie = (u64)_(skops->sk);
	probe_read_kernel(&cookie, sizeof(cookie), &__cookie);
	socket = lookup_socketmap(&cookie);
	if (!socket) {
		emit_ip_error_event(skops, 0, &cookie, _(skops->family) == AF_INET6, 0, 0, 0, IP_ERROR_TCP_CONNECT_NO_PROCESS);
		return 0;
	}

	// Set the protocol here because it probably wasn't specified at the time of
	// socket allocation.
	socket->protocol = IPPROTO_TCP;

	key = &socket->key;
	val = (struct msg_ip_with_tnp_event *)map_lookup_elem(&tg_h_event,
							      &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_TCPCONNECTRET;
	skops_socket(cookie, (struct msg_ip_event *)val, socket);
	skops_tuple(cookie, (struct msg_ip_event *)val, skops);
	val->tuple.proto = IPPROTO_TCP;
	val->policy_id = 0;
	val->rule_id = 0;
	val->verdict = 0;

	struct tcpsocketmap_value *v = init_tcpsocketmap_value(key, _(skops->family), SOCKFLAGS_TYPE_CONNECT, socket->create_time, socket->version, &val->tuple);
	if (v) {
		// We're not actually denying anything at this point. The deny happens
		// at send/recv time. But it's interesting to export what the verdict
		// _would_ be at the time the connection happens. At any rate,
		// Hypershield folks need this information, so let's include it in the
		// event and document the behaviour.
		v->deny = process_socketmap_add(v, &(val->tuple));
		val->verdict = v->deny;
		DEBUG("VERDICT: %d", val->verdict);

		dest = map_lookup_elem(&destination_endpoint_map, &v->dst_key);
		if (dest) {
			DEBUG("POLCIY ID: %d", dest->policy);
			DEBUG("RULE:      %d", dest->rule);
			val->policy_id = dest->policy;
			val->rule_id = dest->rule;
		}
		add_tcpsocketmap(&cookie, v, true);
	}

	event_post_connect(skops, val);
	return 0;
}

int event_tcp_close_sockops(struct bpf_sock_ops *skops)
{
	struct tcp_event_disable_config *event_cfg;
	struct msg_ip_with_stats_event *val;
	struct tcpsocketmap_value *socket;
	struct cfg_value *l3cfg;
	int old_state, state;
	u64 cookie, __cookie;
	u32 zero = 0;
	size_t size;

	/* In TCP we use the struct sock address as the socket cookie.
	 * Verifier on 6.15 (maybe earlier) maintained that cookie was a sock-or-null and
	 * didn't want to pass it to the skops_tuple() function as a scalar. This
	 * construction converts the sock-or-null to a scalar. Note, probe_reading
	 * directly from the _(skops->sk) caused confusion so should be avoided.
	*/
	__cookie = (u64)_(skops->sk);
	probe_read_kernel(&cookie, sizeof(cookie), &__cookie);

	old_state = _(skops->args[0]);
	state = _(skops->args[1]);

	if (state != TCP_CLOSE)
		return 0;

	socket = lookup_tcpsocketmap(&cookie);
	if (!socket) {
		// Don't report an error here if the TCP socket isn't yet active.
		if (tcp_active(old_state))
			emit_ip_error_event(skops, 0, &cookie, false, 0, 0, 0, IP_ERROR_TCP_CLOSE_NO_SOCKET);
		return 0;
	}

	/* We don't need to account further if the socket has already been closed. */
	if (socket->closed)
		return 0;

	val = (struct msg_ip_with_stats_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_TCPCLOSE;
	skops_socket_with_stats(cookie, val, socket);
	val->tuple = socket->tuple;
	if (old_state == TCP_SYN_SENT)
		val->socket_flags |= SOCKFLAGS_CONNECT_FAILED;
	get_socket_stats((struct sock *)cookie, socket, &val->stats);
	val->close_time = tg_get_ktime();
	socket->closed = 1;

	l3cfg = getl3cfg();
	if (!l3cfg)
		return 0;
	event_cfg = &l3cfg->tcp_disable;

	size = sizeof(struct msg_ip_with_stats_event);
	if (!event_cfg->disableClose) {
		perf_event_output_metric(skops, ISO_MSG_OP_TCPCLOSE, &tcpmon_map,
					 BPF_F_CURRENT_CPU, val, size);
	}

	if (!socket->tuple.ipv6) {
		del_tlsmap(&cookie);
		map_delete_elem(&tg_http_map, &cookie);
		bottle_drop(&cookie);
	}

	return 0;
}

__attribute__((section("sockops/tcp_sockops"), used)) int
tg_event_tcp_sockops(struct bpf_sock_ops *skops)
{
	__u32 family = _(skops->family);
	__u32 op = _(skops->op);

	if (family != AF_INET && family != AF_INET6)
		return 0;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		event_tcp_sockops_connect(skops);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		event_tcp_close_sockops(skops);
		break;
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		event_tcp_sockops_listen(skops);
		break;
	default:
		break;
	}
	return 0;
}
