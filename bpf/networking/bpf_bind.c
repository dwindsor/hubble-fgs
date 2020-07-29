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

__attribute__((section(("kprobe/sys_bind")), used))
int event_bind(struct pt_regs *ctx)
{
#if 0
	struct msg_ipv4_tcp_event *value;
	struct msg_ipv4_tcp_key *key;
	struct sockaddr_in *in_addr;
	__u16 proto;

	key.pid = (get_current_pid_tgid() >> 32);

	probe_read(&in_addr, sizeof(in_addr), &ctx->si);
	if (in_addr) {
		probe_read(&proto, sizeof(proto), _(&in_addr->sin_family));
		probe_read(&key.saddr, sizeof(msg->tuple.saddr), _(&in_addr->sin_addr.s_addr));
		probe_read(&key.sport, sizeof(msg->tuple.sport), _(&in_addr->sin_port));
	}

	map_update_elem(&ipv4_tcp_map, &key, &value);	
	msg->common.size = 1; // stand-in until we complete calculation from listen
#endif
	return 1;
}
