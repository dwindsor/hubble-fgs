#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/inet_hash")), used))
int event_sys_listen(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_event value = {0};
	struct execve_map_value *process = 0;
	struct msg_ipv4_tcp_key key;
	__u32 pid, ppid = 0;
	struct sock *skp;
	bool walker = 0;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, 0, &walker);
	if (!process)
		return 0;

	skp = (void *)((ctx)->di);
	probe_read(&key.saddr, sizeof(key.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&key.sport, sizeof(key.sport), _(&(skp->__sk_common.skc_num)));
	key.pid = pid;
	key.pad = 0;

	value.tuple.saddr = key.saddr;
	value.tuple.sport = key.sport;
	value.common.op = MSG_OP_IPV4_LISTEN;
	value.common.size = sizeof(struct msg_ipv4_tcp_event);
	value.key.pid = pid;
	value.key.ktime = process->key.ktime;

	map_update_elem(&ipv4_tcp_map, &key, &value, 0);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &value, sizeof(struct msg_ipv4_tcp_event));
	return 0;
}
