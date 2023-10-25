#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "bpf_task.h"
#include "cookie.h"
#include "netns.h"
#include "tlsmsg.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tracing.h"
#include "bpf_network_event_config.h"

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
} tcp_listen_event_map SEC(".maps");

__attribute__((section("kprobe/__inet_hash"), used)) int
tg_event_sys_listen(struct pt_regs *ctx)
{
	struct msg_ip_event *val;
	struct execve_map_value *process = 0;
	__u32 pid, ppid = 0, zero = 0;
	struct sock *skp;
	bool walker = 0;
	u16 family;
	u64 cookie;
	struct tcp_event_disable_config *event_cfg;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, &walker);
	if (!process)
		return 0;

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_listen_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	skp = (struct sock *)PT_REGS_PARM1(ctx);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	*val = (struct msg_ip_event){
		.tuple.daddr[0] = 0,
		.tuple.daddr[1] = 0,
		.tuple.dport = 0,
		.common.op = ISO_MSG_OP_LISTEN,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.pad = 0,
		.duration = 0,
	};

	probe_read(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	probe_read(&val->tuple.sport, sizeof(val->tuple.sport),
		   _(&(skp->__sk_common.skc_num)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read(&val->tuple.saddr[0], sizeof(__u32),
			   _(&(skp->__sk_common.skc_rcv_saddr)));
	} else {
		val->tuple.ipv6 = true;
		probe_read(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
			   _(&(skp->__sk_common.skc_v6_rcv_saddr)));
	}
	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	if (!event_cfg->disableListen) {
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				  sizeof(struct msg_ip_event));
	}

	struct socketmap_value v = { 0 };

	v.key.pid = process->key.pid;
	v.key.ktime = process->key.ktime;
	v.create_time = val->common.ktime;
	v.create_time = val->common.ktime;
	v.zero_window = 0;
	v.socket_flags |= SOCKFLAGS_TYPE_LISTEN;
	v.sent = 0;
	v.received = 0;
	v.tuple.saddr[0] = val->tuple.saddr[0];
	v.tuple.saddr[1] = val->tuple.saddr[1];
	v.tuple.daddr[0] = v.tuple.daddr[1] = 0;
	v.tuple.ipv6 = (family == AF_INET6);
	v.tuple.dport = 0;
	v.tuple.sport = val->tuple.sport;
	v.tuple.proto = IPPROTO_TCP;

	add_socketmap(&cookie, &v);
	return 0;
}
