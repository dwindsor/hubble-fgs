// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "bpf_task.h"
#include "networkmsg.h"
#include "bpf_tracing.h"

/* set_tuple_from_skb(skb)
 *
 *  Fill in the msg_ip_tuple and return whether we should output this (true)
 *  or not (false).
 *
 * NB: this is a best-effort function to retrieve a 5-tuple from an sk_buff
 * structure. Result is _not_ guaranteed to be valid.
 */
static inline bool __attribute__((unused))
set_tuple_from_skb(struct msg_ip_tuple *tuple, struct sk_buff *skb)
{
	unsigned char *skb_head = 0;
	u16 l3_off;

	probe_read_kernel(&skb_head, sizeof(skb_head), _(&skb->head));
	probe_read_kernel(&l3_off, sizeof(l3_off), _(&skb->network_header));

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	probe_read_kernel(&iphdr_byte0, 1, _(ip));

	u8 ip_ver = iphdr_byte0 >> 4;
	if (ip_ver == 4) { // IPv4
		u8 v4_prot;
		probe_read_kernel(&v4_prot, 1, _(&ip->protocol));

		tuple->proto = v4_prot;
		tuple->ipv6 = false;

		probe_read_kernel(&tuple->saddr[0], sizeof(ip->saddr), _(&ip->saddr));
		probe_read_kernel(&tuple->daddr[0], sizeof(ip->daddr), _(&ip->daddr));
		typeof(skb->transport_header) l4_off;
		probe_read_kernel(&l4_off, sizeof(l4_off), _(&skb->transport_header));
		if (v4_prot == 0x06) { // TCP
			struct tcphdr *tcp =
				(struct tcphdr *)(skb_head + l4_off);
			probe_read_kernel(&tuple->sport, sizeof(tuple->sport),
					  _(&tcp->source));
			probe_read_kernel(&tuple->dport, sizeof(tuple->dport),
					  _(&tcp->dest));
		} else if (v4_prot == 0x11) { // UDP
			struct udphdr *udp =
				(struct udphdr *)(skb_head + l4_off);
			probe_read_kernel(&tuple->sport, sizeof(tuple->sport),
					  _(&udp->source));
			probe_read_kernel(&tuple->dport, sizeof(tuple->dport),
					  _(&udp->dest));
		}
		tuple->sport = bpf_ntohs(tuple->sport);
		tuple->dport = bpf_ntohs(tuple->dport);
		return true;
	} else if (ip_ver == 6) {
		// NB: we need to add IPv6 parsing here, but until we do we just
		// return true so that the caller will emit the message (with the
		// stacktrace).
		return true;
	}

	// This is not IP, so we probably don't care. Don't emit message.
	return false;
}

__attribute__((section("kprobe/kfree_skb"), used)) int
tg_event_kfree_skb(struct pt_regs *ctx)
{
	struct msg_kfree_skb msg = { 0 };
	bool emit;

	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);

	emit = set_tuple_from_skb(&msg.tuple, skb);
	if (!emit)
		return 1;

	// TODO: fill the common part with process info/timestamp/etc.
	msg.common.op = ISO_MSG_OP_KFREE_SKB;
	msg.calltrace.ret = get_stack(ctx, &msg.calltrace.stack,
				      sizeof(msg.calltrace.stack), 0);
	perf_event_output_metric(ctx, ISO_MSG_OP_KFREE_SKB, &tcpmon_map, BPF_F_CURRENT_CPU, &msg,
				 sizeof(msg));
	return 1;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif
