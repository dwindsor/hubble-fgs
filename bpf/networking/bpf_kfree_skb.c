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


/* set_tuple_from_skb(skb)
 *
 *  Fill in the msg_ipv4_tuple and return whether we should output this (true)
 *  or not (false).
 *
 * NB: this is a best-effort function to retreive a 5-tuple from an sk_buff
 * structure. Result is _not_ guaranteed to be valid.
 *
 * TODO: We should modify the code to use BTF information when accessing the
 * kernel structures below.
 */
static inline bool
__attribute__((unused))
set_tuple_from_skb(struct msg_ipv4_tuple *tuple, struct sk_buff *skb) {

	unsigned char *skb_head = 0;
	u16 l3_off;

	probe_read(&skb_head, sizeof(skb_head), _(&skb->head));
	probe_read(&l3_off, sizeof(l3_off), _(&skb->network_header));

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	probe_read(&iphdr_byte0, 1, _(ip));
	if ((iphdr_byte0>>4) == 4) { // IPv4
		u8 v4_prot;
		probe_read(&v4_prot, 1, _(&ip->protocol));

		// NB: not sure what exactly is expected for ->proto, so fill
		// the v4 header field for now
		tuple->proto = v4_prot;

		probe_read(&tuple->saddr, sizeof(tuple->saddr), _(&ip->saddr));
		probe_read(&tuple->daddr, sizeof(tuple->daddr), _(&ip->daddr));
		typeof(skb->transport_header) l4_off;
		probe_read(&l4_off, sizeof(l4_off), _(&skb->transport_header));
		if (v4_prot == 0x06) { // TCP
			// unstable API.
			struct tcphdr *tcp = (struct tcphdr *)(skb_head + l4_off);
			probe_read(&tuple->sport, sizeof(tuple->sport), _(&tcp->source));
			probe_read(&tuple->dport, sizeof(tuple->dport), _(&tcp->dest));
		} else if (v4_prot == 0x11) { // UDP
			// unstable API.
			struct udphdr *udp = (struct udphdr *)(skb_head + l4_off);
			probe_read(&tuple->sport, sizeof(tuple->sport), _(&udp->source));
			probe_read(&tuple->dport, sizeof(tuple->dport), _(&udp->dest));
		}
		return true;
	}

	return false;
}


__attribute__((section(("kprobe/kfree_skb")), used))
int event_kfree_skb(struct pt_regs *ctx) {
	struct msg_kfree_skb msg = {0};
	bool emit;

	struct sk_buff *skb = (void *)ctx->di;

	emit = set_tuple_from_skb(&msg.tuple, skb);
	if (!emit)
		return 1;

	// TODO: fill the common part with process info/timestamp/etc.
	msg.common.op = MSG_OP_KFREE_SKB;
	msg.calltrace.ret = get_stack(ctx, &msg.calltrace.stack, sizeof(msg.calltrace.stack), 0);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	return 1;
}


char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif
