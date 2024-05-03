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

__attribute__((section("kprobe/tcp_connect"), used)) int
tg_event_tcp_connect(struct pt_regs *ctx)
{
	struct tcp_event_disable_config *event_cfg;
	struct execve_map_value *process = 0;
	struct msg_ip_event *val;
	__u32 ppid = 0, zero = 0;
	struct sock *skp;
	bool walker = 0;
	u16 family;
	uint64_t size;
	u64 cookie;

	process = event_find_curr(&ppid, &walker);
	if (!process)
		return 0;

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_connect_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	skp = (struct sock *)PT_REGS_PARM1(ctx);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	*val = (struct msg_ip_event){
		.common.op = ISO_MSG_OP_TCPCONNECTRET,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.version = 0,
		.duration = 0,
	};

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

	event_cfg = (struct tcp_event_disable_config *)
		map_lookup_elem(&tg_event_disable_config, &zero);

	if (!event_cfg)
		return 0;

	if (!event_cfg->disableConnect) {
		size = sizeof(struct msg_ip_event);
		perf_event_output_metric(ctx, ISO_MSG_OP_TCPCONNECTRET, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	}

	struct tcpsocketmap_value v = { 0 };
	v.key.pid = process->key.pid;
	v.key.ktime = process->key.ktime;
	v.create_time = val->common.ktime;
	v.last_time = v.create_time;
	v.socket_flags |= SOCKFLAGS_TYPE_CONNECT;
	v.sent = 0;
	v.received = 0;
	v.tuple.saddr[0] = val->tuple.saddr[0];
	v.tuple.saddr[1] = val->tuple.saddr[1];
	v.tuple.daddr[0] = val->tuple.daddr[0];
	v.tuple.daddr[1] = val->tuple.daddr[1];
	v.tuple.ipv6 = (family == AF_INET6);
	v.tuple.dport = val->tuple.dport;
	v.tuple.sport = val->tuple.sport;
	v.tuple.proto = IPPROTO_TCP;
	v.version = cookie_inc_version();

	add_tcpsocketmap(&cookie, &v, true);

	struct socketmap_value sockproc = { 0 };
	sockproc.create_time = val->common.ktime;
	sockproc.key = process->key;
	sockproc.protocol = IPPROTO_TCP;
	sockproc.version = v.version;
	add_socketmap(&cookie, &sockproc, false);
	return 1;
}
