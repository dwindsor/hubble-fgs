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
	val->create_time = socket->create_time;
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

__attribute__((section("sockops/tcp_sockops"), used)) int
tg_event_tcp_sockops(struct bpf_sock_ops *skops)
{
	__u32 family = skops->family;

	if (family != AF_INET && family != AF_INET6)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		__event_tcp_connect_sockops(skops);
		break;
	default:
		break;
	}
	return 0;
}
