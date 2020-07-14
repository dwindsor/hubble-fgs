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
	struct msg_ipv4_tcp_connect *msg = 0;
	__u32 ppid = 0, pid = 0;
	struct sockaddr *uaddr;
	struct sockaddr_in *in;
	struct socket *sockp;
	struct sock *skp;
	bool walker = 0;

	pid = (get_current_pid_tgid() >> 32);
	msg = event_find_curr(&ppid, &msg_ipv4_tcp_map, &walker);
	if (!msg)
		return 0;

	sockp = (void *)((ctx)->di);
	probe_read(&skp, sizeof(skp), _(&(sockp->sk)));
	if (!skp) {
		msg->common.flags |= EVENT_ERROR_SOCK;
		goto out;
	}
	uaddr = (void *)((ctx)->si);
	in = (struct sockaddr_in *)uaddr;
	probe_read(&msg->tuple.daddr, sizeof(msg->tuple.daddr), _(&(in->sin_addr)));
	probe_read(&msg->tuple.dport, sizeof(msg->tuple.dport), _(&(in->sin_port)));
out:
	event_get_task_info(msg, MSG_OP_IPV4_TCPCONNECT, walker);
	return 1;
}
