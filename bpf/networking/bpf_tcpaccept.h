#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_fd_to_sk.h"
#include "netns.h"

struct bpf_map_def __attribute__((section("maps"), used))
tcp_accept_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ip_event),
	.max_entries = 1,
};

struct accept_args {
	u64 pad;
	int syscall_nr;
	int pad2;
	long ret;
};

static inline __attribute__((always_inline)) int
__event_tcp4_acceptret(struct accept_args *ctx, bool pre56)
{
	struct msg_ip_event *val;
	struct execve_map_value *process;
	struct socketmap_value *acc_process;
	struct msg_tls_ipv4 tuple;
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

	fd = ctx->ret;
	if (fd < 0)
		return 0;

	skp = fd_to_sk(current, fd, IPPROTO_TCP, pre56, &read_ok, &family);
	if (!skp)
		return 0;

	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	probe_read(&tuple.saddr, sizeof(tuple.saddr),
		   _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr),
		   _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));
	tuple.remaining = 0;
	tuple.uid = 0;

	if (is_tuple_local(&tuple))
		tuple.uid = sock_netns(skp);

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_accept_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),
		.common.op = ISO_MSG_OP_TCPACCEPT,
		.tuple.ipv6 = false,
		.tuple.saddr[0] = tuple.saddr,
		.tuple.saddr[1] = 0,
		.tuple.daddr[0] = tuple.daddr,
		.tuple.daddr[1] = 0,
		.tuple.dport = tuple.dport,
		.tuple.sport = tuple.sport,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.pad = 0,
	};

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

	acc_process = map_lookup_elem(&socket_map_heap, &zero);
	if (!acc_process)
		return 0;

	acc_process->key.pid = process->key.pid;
	acc_process->key.ktime = process->key.ktime;
	acc_process->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
	acc_process->last_time = 0;
	acc_process->received = 0;
	acc_process->sent = 0;
	acc_process->zero_window = 0;

	add_socketmap(&cookie, &tuple, acc_process);

	return 1;
}
