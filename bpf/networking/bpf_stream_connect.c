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

__attribute__((section(("kprobe/__inet_stream_connect")), used))
int event_stream_connect(struct pt_regs *ctx)
{
	struct msg_execve_event *process = 0;
	struct msg_ipv4_tcp_event value;
	struct msg_ipv4_tcp_key key;
	struct event_execve *curr;
	__u32 ppid = 0, pid = 0;
	struct sockaddr *uaddr;
	struct sockaddr_in *in;
	struct socket *sockp;
	struct inet_sock *skp;
	bool walker = 0;
	__u32 daddr;
	__u16 dport;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, 0, &walker);
	if (!process)
		return 0;

	sockp = (void *)((ctx)->di);
	probe_read(&skp, sizeof(skp), _(&(sockp->sk)));
	if (!skp) {
		process->common.flags |= EVENT_ERROR_SOCK;
		goto out;
	}
	uaddr = (void *)((ctx)->si);
	in = (struct sockaddr_in *)uaddr;
	key.pid = pid;
	key.pad = 0;
	key.saddr = 0;
	//probe_read(&key.saddr, sizeof(key.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&key.sport, sizeof(key.sport), _(&(skp->inet_sport)));
	probe_read(&daddr, sizeof(daddr), _(&(in->sin_addr)));
	probe_read(&dport, sizeof(dport), _(&(in->sin_port)));
	bpf_printk("stream probed %d %d %d\n", pid, key.saddr, key.sport);
	bpf_printk("stream probed %d %d %d\n", pid, daddr, dport);

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

	value.key.pid = pid;
	curr = event_get_curr_execve(process);
	if (curr)
		value.key.ktime = curr->ktime;
	else
		value.key.ktime = 0; // This is an error case
	bpf_printk("stream update kprobe event %d %d %d\n", key.pid, key.saddr, key.sport);
	map_update_elem(&ipv4_tcp_map, &key, &value, 0);
out:
	return 1;
}
