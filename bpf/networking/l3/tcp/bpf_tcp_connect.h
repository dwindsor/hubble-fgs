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
#include "iso_msg_types.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "lib/netns.h"
#include "tlsmsg.h"
#include "parsers/tls/tls_map.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tracing.h"
#include "bpf_tcp_network_event_config.h"
#include "bpf_tcp_info.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_state.h"

#ifdef KERNEL_5_15
#include "process/process_tree.h"
#endif

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_connect_event_map SEC(".maps");

static inline __attribute__((always_inline)) struct msg_ip_event init_msg_ip_event(struct msg_execve_key *key, u64 cookie)
{
	return (struct msg_ip_event){
		.common.op = ISO_MSG_OP_TCPCONNECTRET,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = key->pid,
		.key.ktime = key->ktime,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.version = 0,
		.create_time = 0,
		.close_time = 0,
	};
}

static inline __attribute__((always_inline)) int
event_post_connect(void *ctx, struct msg_ip_event *val)
{
	struct tcp_event_disable_config *event_cfg;
	int zero = 0;

	event_cfg = (struct tcp_event_disable_config *)
		map_lookup_elem(&tg_event_disable_config, &zero);

	if (!event_cfg)
		return 0;

	if (!event_cfg->disableConnect) {
		uint64_t size = sizeof(struct msg_ip_event);

		perf_event_output_metric(ctx, ISO_MSG_OP_TCPCONNECTRET, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	}
	return 0;
}

static inline __attribute__((always_inline)) int
__event_tcp_connect(void *ctx, struct sock *skp)
{
	struct execve_map_value *process = 0;
	struct socketmap_value *socket = 0;
	struct tcpsocketmap_value *v = 0;
	struct msg_execve_key *key;
	struct msg_ip_event *val;
	__u32 ppid = 0, zero = 0;
	bool walker = 0;
	u16 family;
	u64 cookie;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (u64)skp;

	socket = lookup_socketmap(&cookie);
	if (socket) {
		key = &socket->key;
		// Set the protocol here because it probably wasn't specified at the time of
		// socket allocation.
		socket->protocol = IPPROTO_TCP;
	} else {
		/* We shouldn't need this fall back. */
		process = event_find_curr(&ppid, &walker);
		if (!process) {
			emit_ip_error_event(ctx, 0, &cookie, false, 0, 0, 0, IP_ERROR_TCP_CONNECT_NO_PROCESS);
			return 0;
		}
		key = &process->key;
	}

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_connect_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	*val = init_msg_ip_event(key, cookie);
	if (socket)
		val->version = socket->version;

	val->tuple.proto = IPPROTO_TCP;
	probe_read_kernel(&val->tuple.sport, sizeof(val->tuple.sport),
			  _(&(skp->__sk_common.skc_num)));
	probe_read_kernel(&val->tuple.dport, sizeof(val->tuple.dport),
			  _(&(skp->__sk_common.skc_dport)));
	val->tuple.dport = bpf_ntohs(val->tuple.dport);

	probe_read_kernel(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(__u32),
				  _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
		probe_read_kernel(&val->tuple.daddr[0], sizeof(__u32),
				  _(&(skp->__sk_common.skc_daddr)));
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
				  _(&(skp->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
				  _(&(skp->__sk_common.skc_v6_daddr)));
	}

	event_post_connect(ctx, val);

	if (key && socket)
		v = init_tcpsocketmap_value(key, family, SOCKFLAGS_TYPE_CONNECT, socket->create_time, socket->version, &val->tuple);
	if (v) {
#ifdef KERNEL_5_15
		process_socketmap_add(v, &(val->tuple));
#endif
		add_tcpsocketmap(&cookie, v, true);
	}
	return 1;
}
