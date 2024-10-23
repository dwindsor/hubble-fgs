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
#define KERNEL_5_15 // This may be relaxed in future releases

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "socktrack/bpf_sk_alloc.h"
#include "lib/address_family.h"
#include "bpf_tcp_accept.h"
#include "bpf_tcp_listen.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct tcpsocketmap_value);
	__uint(max_entries, 1);
} tg_listen_socket SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct socketmap_value);
	__uint(max_entries, 1);
} tg_listen_process SEC(".maps");

/* Theory of Operations: The kernel does not at the moment have a hook that
 * is reliable to capture both the listen sock and the new sock from the
 * accept. In the past we've glue'd the enter/exit of child sock create
 * logic in the kernel. And then another kprobe on actual accept. The result
 * was 2 kprobe + 1 kprobe_ret. This was rather slow. See Tetragon 1.14
 * versions for the details. I decided its more obvious to have two security
 * hooks instead. First we hook security_socket_accept(socket, newsocket) and
 * create a map from newsocket->(socket->sk). This is done because newsocket
 * does not yet have its sock struct attached yet. Then on security_sock_graft
 * we can use the map to get the listen sk of the newsk being grafted. Here
 * we create the accept event along with update the tcpsocketmap and socketmaps.
 */
SEC("fentry/security_socket_accept")
int BPF_PROG(tg_security_socket_accept, struct socket *sock, struct socket *newsocket)
{
	u64 cookie = (u64)newsocket;
	u64 sk = (u64)sock->sk;

	map_update_elem(&tg_tcp_accept_socket_to_sk_map, &cookie, &sk, 0);
	return 0;
}

SEC("fentry/security_sock_graft")
int BPF_PROG(tg_security_sock_graft, struct sock *sk, struct socket *parent)
{
	struct tcp_event_disable_config *event_cfg;
	struct tcpsocketmap_value *listen_socket = 0;
	struct socketmap_value *listen_process = 0;
	struct msg_ip_tuple tuple = { 0 };
	struct msg_ip_event *event;
	u64 now = ktime_get_ns();
	u16 family, protocol;
	u32 zero = 0;

	u64 *cookie, listen_cookie = 0;
	u64 cookie_version = 0;
	u64 newcookie, parent_cookie = (u64)parent;

	probe_read_kernel(&family, sizeof(family), _(&(sk->__sk_common.skc_family)));

	if (family != AF_INET && family != AF_INET6)
		return 0;

	cookie = map_lookup_elem(&tg_tcp_accept_socket_to_sk_map, &parent_cookie);
	if (likely(cookie)) {
		listen_cookie = (u64)*cookie;
		listen_process = lookup_socketmap(&listen_cookie);
		listen_socket = lookup_tcpsocketmap(&listen_cookie);
	}
	newcookie = (u64)sk;

	/* This is to handle the case where a socket is blocking on accept
	 * when Tetragon started. In this case the socket created on accept()
	 * will not have an entry yet in the tg_tcp_accept_socket_to_sk_map.
	 * Nor will it have an entry in the socketmap because the socket
	 * create was before starting Tetragon as well. This means we will
	 * not be able to find its parent listen socket. So we need to find
	 * listen process directly. However, its rare and next accept will
	 * work so mark it unlikely.
	 */
	if (unlikely(!listen_process)) {
		struct execve_map_value *value;
		bool walked;
		u32 ppid;

		listen_process = map_lookup_elem(&tg_listen_process, &zero);
		if (!listen_process)
			return 0;

		value = event_find_curr(&ppid, &walked);
		if (!value)
			return 0;
		listen_process->key.pid = value->key.pid;
		listen_process->key.ktime = value->key.ktime;
		listen_process->create_time = ktime_get_ns();
		listen_process->version = 0;
		listen_process->protocol = 0;
		memset(&listen_process->pad, 0, 7);
	}

	/* Similar to above if the tg_tcp_accept_socket_to_sk_map did not
	 * find an entry because of blocking accept() at Tetragon startup
	 * we will need to populate the key to the listen socket directly.
	 */
	if (unlikely(!listen_socket)) {
		listen_socket = map_lookup_elem(&tg_listen_socket, &zero);
		if (!listen_socket) {
			return 0;
		}

		listen_socket->key = listen_process->key;
	}

	if (family == AF_INET6) {
		tuple.ipv6 = 1;
		probe_read_kernel(tuple.saddr, sizeof(tuple.saddr), _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(tuple.daddr, sizeof(tuple.daddr), _(&(sk->__sk_common.skc_v6_daddr)));
	} else {
		probe_read_kernel(&tuple.saddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_rcv_saddr)));
		probe_read_kernel(&tuple.daddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_daddr)));
	}
	probe_read_kernel(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32)) {
		protocol >>= 8;
	}
	tuple.proto = protocol;
	probe_read_kernel(&tuple.sport, sizeof(tuple.sport), _(&(sk->__sk_common.skc_num)));
	probe_read_kernel(&tuple.dport, sizeof(tuple.dport), _(&(sk->__sk_common.skc_dport)));
	tuple.dport = bpf_ntohs(tuple.dport);

	cookie_version = cookie_inc_version();

	// These if (1) blocks are here to help compiler with stack allocation
	// this is enough to keep stack limit below 512.
	if (1) {
		struct socketmap_value accept_process = *listen_process;

		accept_process.version = cookie_version;
		accept_process.create_time = now;
		add_socketmap(&newcookie, &accept_process, &tuple, true);
	}

	if (1) {
		struct tcpsocketmap_value accept_socket = *listen_socket;

		accept_socket.version = cookie_version;
		accept_socket.stats.create_time = now;
		accept_socket.socket_flags = SOCKFLAGS_TYPE_ACCEPT;
		accept_socket.stats.sk_drops = 0;
		accept_socket.fin_rx = 0;
		add_tcpsocketmap(&newcookie, &accept_socket, &tuple, true);
	}

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	if (!event_cfg->disableAccept) {
		size_t size = sizeof(struct msg_ip_event);

		event = (struct msg_ip_event *)map_lookup_elem(&tcp_accept_event_map,
							       &zero);
		if (!event)
			return 0;

		event->common.op = ISO_MSG_OP_TCPACCEPT;
		event->common.size = sizeof(struct msg_ip_event);
		event->common.ktime = now;
		event->socket_cookie = newcookie;
		event->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
		event->version = cookie_version;
		event->create_time = now;
		event->close_time = 0;

		event->tuple = tuple;
		event->key = listen_process->key;

		perf_event_output_metric(ctx, ISO_MSG_OP_TCPACCEPT, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	}
	return 0;
}
