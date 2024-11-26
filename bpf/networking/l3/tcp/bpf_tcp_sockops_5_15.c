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

#define KERNEL_5_15
#include "bpf_tcp_connect.h"
#include "bpf_tcp_state.h"
#include "bpf_tcp_listen.h"
#include "bpf_tcp_accept.h"
#include "parsers/http/http_parser.h"
#include "parsers/bottle.h"

int skops_socket(u64 cookie, struct msg_ip_event *val, struct socketmap_value *socket)
{
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = ktime_get_ns();
	val->socket_cookie = cookie;
	val->socket_flags = 0;
	val->version = socket->version;
	val->key.pid = socket->key.pid;
	val->key.ktime = socket->key.ktime;
	val->create_time = socket->create_time;

	return 0;
}

int skops_tcpsocket(u64 cookie, struct msg_ip_event *val, struct tcpsocketmap_value *socket)
{
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = ktime_get_ns();
	val->socket_cookie = cookie;
	val->socket_flags = 0;
	val->version = socket->version;
	val->key.pid = socket->key.pid;
	val->key.ktime = socket->key.ktime;
	val->create_time = socket->stats.create_time;
	val->socket_flags = socket->socket_flags;

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

	val->tuple.sport = skops->local_port;
	probe_read_kernel(&val->tuple.dport, sizeof(val->tuple.dport),
			  _(&(((struct sock *)cookie)->__sk_common.skc_dport)));
	val->tuple.dport = bpf_ntohs(val->tuple.dport);

	if (skops->family != AF_INET6) {
		val->tuple.ipv6 = false;
		val->tuple.saddr[0] = skops->local_ip4;
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[0] = skops->remote_ip4;
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
				  _(&(((struct sock *)cookie)->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
				  _(&(((struct sock *)cookie)->__sk_common.skc_v6_daddr)));
	}

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
	u64 cookie, now;
	struct msg_ip_event *val;
	u32 zero = 0;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (u64)skops->sk;
	socket = lookup_socketmap(&cookie);
	if (!socket)
		return 0;

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_listen_event_map,
						     &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_LISTEN;
	skops_socket(cookie, val, socket);
	skops_tuple(cookie, val, skops);

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	if (!event_cfg->disableListen) {
		perf_event_output_metric(skops, ISO_MSG_OP_LISTEN, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					 sizeof(struct msg_ip_event));
	}

	v = map_lookup_elem(&tg_sockops_tcpsocket_map, &zero);
	if (!v)
		return 0;

	now = ktime_get_ns();

	v->key.pid = val->key.pid;
	v->key.ktime = val->key.ktime;
	v->stats.create_time = now;
	v->stats.ktime = now;
	v->stats.zero_window = 0;
	v->socket_flags = SOCKFLAGS_TYPE_LISTEN;
	v->stats.bytes_sent = 0;
	v->stats.bytes_received = 0;
	v->stats.segs_out = 0;
	v->stats.segs_in = 0;
	v->stats.sk_drops = 0;
	v->fin_rx = 0;
	v->ipv6 = (skops->family == AF_INET6);
	v->version = val->version;

	add_tcpsocketmap(&cookie, v, &val->tuple, true);

	return 0;
}

int event_tcp_sockops_connect(struct bpf_sock_ops *skops)
{
	struct socketmap_value *socket = 0;
	struct msg_execve_key *key;
	struct msg_ip_event *val;
	__u32 zero = 0;
	u64 cookie;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (__u64)skops->sk;
	socket = lookup_socketmap(&cookie);
	if (!socket) {
		emit_ip_error_event(skops, 0, &cookie, skops->family == AF_INET6, 0, 0, 0, IP_ERROR_TCP_CONNECT_NO_PROCESS);
		return 0;
	}

	key = &socket->key;
	val = (struct msg_ip_event *)map_lookup_elem(&tcp_connect_event_map,
						     &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_TCPCONNECTRET;
	skops_socket(cookie, val, socket);
	skops_tuple(cookie, val, skops);

	event_post_connect(skops, val);

	struct tcpsocketmap_value *v = init_tcpsocketmap_value(val, key, skops->family);
	if (!v)
		return 0;
#ifdef KERNEL_5_15
	process_socketmap_add(v, &(val->tuple));
#endif
	add_tcpsocketmap(&cookie, v, &val->tuple, true);
	return 0;
}

int event_tcp_close_sockops(struct bpf_sock_ops *skops)
{
	struct tcp_event_disable_config *event_cfg;
	struct msg_ip_with_stats_event *val;
	struct tcpsocketmap_value *socket;
	int old_state, state;
	u32 zero = 0;
	size_t size;
	u64 cookie;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (u64)skops->sk;

	old_state = skops->args[0];
	state = skops->args[1];

	if (state == TCP_CLOSE_WAIT || state == TCP_CLOSING ||
	    (old_state == TCP_FIN_WAIT2 && state == TCP_TIME_WAIT) ||
	    (old_state == TCP_FIN_WAIT1 && state == TCP_TIME_WAIT))
		return tcp_set_fin(skops, &cookie);

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

	val = (struct msg_ip_with_stats_event *)map_lookup_elem(&tcp_close_event_map, &zero);
	if (!val)
		return 0;

	val->common.op = ISO_MSG_OP_TCPCLOSE;
	skops_socket_with_stats(cookie, val, socket);
	skops_tuple_with_stats(cookie, val, skops);
	get_socket_stats((struct sock *)cookie, socket, &val->stats);
	val->close_time = ktime_get_ns();
	val->stats.bytes_received -= socket->fin_rx;
	socket->closed = 1;

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	size = sizeof(struct msg_ip_with_stats_event);
	if (!event_cfg->disableClose) {
		perf_event_output_metric(skops, ISO_MSG_OP_TCPCLOSE, &tcpmon_map,
					 BPF_F_CURRENT_CPU, val, size);
	}

	if (!socket->ipv6) {
		del_tlsmap(&cookie);
		map_delete_elem(&tg_http_map, &cookie);
		bottle_drop(&cookie);
	}

	return 0;
}

__attribute__((section("sockops/tcp_sockops"), used)) int
tg_event_tcp_sockops(struct bpf_sock_ops *skops)
{
	__u32 family = skops->family;

	if (family != AF_INET && family != AF_INET6)
		return 0;

	switch (skops->op) {
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
