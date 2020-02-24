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

__attribute__((section(("kprobe/inet_bind_hash")), used))
int event_bind_hash(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg = 0;
	unsigned short port;
	bool walker = 0;
	__u32 ppid = 0;

	msg = event_find_curr(&ppid, &msg_ipv4_tcp_map, &walker);
	if (!msg)
		return 0;

	probe_read(&port, sizeof(port), &ctx->dx);
	msg->tuple.sport = port;
	return 1;
}
