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
#include "../parsers/tls/tls_map.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/tcp_v4_send_check")), used))
int event_tcp_v4_send_check(struct pt_regs *ctx)
{
	struct socketmap_value *process;
	struct msg_tls_ipv4 tuple;
	struct tcp_sock *tcp;
	struct net *netns;
	struct sock *skp;
	__u32 rcv_wnd;

	skp = (void *)((ctx)->di);
	tcp = (struct tcp_sock *)skp;

	probe_read(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));
	if (rcv_wnd)
		return 1;

	probe_read(&tuple.saddr, sizeof(tuple.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport), _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr), _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport), _(&(skp->__sk_common.skc_dport)));

	tuple.remaining = 0;
	tuple.uid = 0;

	probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
	if (netns) {
		struct ns_common *c = _(&netns->ns);

		probe_read(&tuple.uid, sizeof(c->inum), _(&c->inum));
	}

	if (!is_tuple_local(&tuple))
		tuple.uid = 0;
	process = lookup_socketmap(&tuple);
	if (process)
		process->zero_window++;
	return 1;
}
