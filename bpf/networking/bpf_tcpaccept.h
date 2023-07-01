#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "cookie.h"
#include "netns.h"
#include "bpf_fd_lookup.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_accept_event_map SEC(".maps");

struct accept_args {
	u64 pad;
	int syscall_nr;
	int pad2;
	long ret;
};

static inline __attribute__((always_inline)) int
__event_tcp_acceptret(struct accept_args *ctx)
{
	struct msg_ip_event *val;
	struct execve_map_value *process;
	struct socketmap_value *acc_process;
	struct msg_tls_ip tuple = { 0 };
	size_t size;
	u32 zero = 0;
	u64 cookie;
	int fd;
	u64 pid = get_current_pid_tgid() >> 32;
	struct task_struct *current = (struct task_struct *)get_current_task();
	struct sock *skp;
	bool read_ok = false;
	u16 family = 0;
	bool walker;
	u32 ppid;
	struct fd_lookup_config *config;
	int skp_err = 0;

	fd = ctx->ret;
	if (fd < 0)
		return 0;

	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;

	skp_err = fd_to_sk(&skp, current, fd, IPPROTO_TCP, &read_ok, &family);
	if (skp_err || !skp)
		return 0;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (u64)skp;

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_accept_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),
		.common.op = ISO_MSG_OP_TCPACCEPT,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.pad = 0,
		.duration = 0,
	};

	probe_read(&val->tuple.sport, sizeof(val->tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&val->tuple.dport, sizeof(val->tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read(&val->tuple.saddr[0], sizeof(u32),
			   _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
		probe_read(&val->tuple.daddr[0], sizeof(u32),
			   _(&(skp->__sk_common.skc_daddr)));
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
			   _(&(skp->__sk_common.skc_v6_rcv_saddr)));
		probe_read(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
			   _(&(skp->__sk_common.skc_v6_daddr)));
	}
	process = event_find_curr(&ppid, &walker);

	if (process) {
		val->key.pid = process->key.pid;
		val->key.ktime = process->key.ktime;
	} else {
		val->key.pid = pid;
		val->key.ktime = 0;
	}

	size = sizeof(struct msg_ip_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);

	if (!process)
		return 0;

	acc_process = (struct socketmap_value *)map_lookup_elem(&tg_socket_map_heap, &zero);
	if (!acc_process)
		return 0;

	acc_process->key.pid = process->key.pid;
	acc_process->key.ktime = process->key.ktime;
	acc_process->create_time = val->common.ktime;
	acc_process->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
	acc_process->last_time = 0;
	acc_process->received = 0;
	acc_process->sent = 0;
	acc_process->zero_window = 0;
	acc_process->ack_finack = 0;

	if (family != AF_INET6) {
		tuple.saddr[0] = val->tuple.saddr[0];
		tuple.daddr[0] = val->tuple.daddr[0];
		tuple.ipv6 = 0;
		tuple.sport = val->tuple.sport;
		tuple.dport = val->tuple.dport;
		tuple.remaining = 0;
		tuple.uid = 0;

		if (is_tuple_local(&tuple))
			tuple.uid = sock_netns(skp);
		add_socketmap(&cookie, &tuple, acc_process);
	} else {
		add_socketmap(&cookie, 0, acc_process);
	}

	return 1;
}
