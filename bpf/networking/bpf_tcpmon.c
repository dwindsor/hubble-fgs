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

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct execve_map_value *process = 0;
	struct msg_ipv4_tcp_event value;
	struct msg_ipv4_tcp_key key;
	__u32 ppid = 0, pid = 0;
	struct sock *skp;
	bool walker = 0;
	uint64_t size;
	__u32 daddr;
	__u16 dport;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, 0, &walker);
	if (!process)
		return 0;

	skp = (void *)((ctx)->di);
	key.pid = pid;
	key.pad = 0;
	probe_read(&key.saddr, sizeof(key.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&key.sport, sizeof(key.sport), _(&(skp->__sk_common.skc_num)));
	probe_read(&daddr, sizeof(daddr), _(&(skp->__sk_common.skc_daddr)));
	probe_read(&dport, sizeof(dport), _(&(skp->__sk_common.skc_dport)));

	value.common.op = MSG_OP_IPV4_TCPCONNECTRET;
	value.common.flags = 0;
	value.common.pad[0] = 0;
	value.common.pad[1] = 0;
	value.common.size = sizeof(struct msg_ipv4_tcp_event);
	value.common.ktime = ktime_get_ns();
	
	value.tuple.saddr = key.saddr;
	value.tuple.daddr = daddr;
	value.tuple.dport = dport;
	value.tuple.sport = key.sport;
	value.tuple.proto = 0;
	value.tuple.post_daddr = 0; // After bpf-cgroup rewrites
	value.tuple.post_dport = 0; // After bpf-cgroup rewrites
	value.tuple.pad[0] = 0;
	value.tuple.pad[1] = 0;
	value.tuple.pad[2] = 0;
	value.tuple.pad[3] = 0;
	value.tuple.pad[4] = 0;

	value.ret = 0; // Populated by kretprobe

	value.key.pid = process->key.pid;
	memset(value.key.pad, 0, sizeof(value.key.pad));
	value.key.ktime = process->key.ktime;
	map_update_elem(&ipv4_tcp_map, &key, &value, 0);

	size = sizeof(struct msg_ipv4_tcp_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &value, size);

	/* tuple is on the stack and verifier wont use stack in call happily
	 * if its not initialized. Alternatively, without padding we are not
	 * 32-bit aligned so we really do want it there.
	 */
	{
		struct msg_execve_key v = {0};
		struct msg_tls_ipv4 tuple;

		tuple.saddr = key.saddr;
		tuple.daddr = daddr;
		tuple.dport = dport;
		tuple.sport = key.sport;
		tuple.proto = 0;
		tuple.pad[0] = 0;
		tuple.pad[1] = 0;
		tuple.pad[2] = 0;

		v.pid = process->key.pid;
		v.ktime = process->key.ktime;

		add_socketmap(&tuple, &v);
	}
	return 1;
}
