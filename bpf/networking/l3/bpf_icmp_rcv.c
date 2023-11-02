#include "vmlinux.h"
#include "bpf_icmp.h"
#include "../udp/bpf_udp_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

// Handles received ICMP packets. We assume they are all linear and
// therefore can be read successfully with probe_read.
__attribute__((section("kprobe/icmp_rcv"), used)) int
tg_icmp_rcv(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	u8 icmp_data[ICMP_HDR_LEN];
	struct msg_icmp_event *val;
	u16 transport_header_off;
	u16 network_header_off;
	struct iphdr *rep_ip4;
	struct tcphdr *tcp;
	struct iphdr ip4;
	struct ihlver iv;
	void *skb_head;
	u16 ethertype;
	int zero = 0;
	u64 cookie;
	u8 version;

	/* Only handle IPv4 and IPv6 here. */
	if (probe_read(&ethertype, sizeof(ethertype), _(&(skb->protocol))) < 0)
		return 0;
	ethertype = bpf_ntohs(ethertype);
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return 0;

	probe_read(&cookie, sizeof(cookie), _(&(skb->sk)));

	version = get_ip_version(&network_header_off, &skb_head, skb);

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return 0;

	val->tuple.send = 0;

	switch (version) {
	case 4:
		if (!get_ip4_header(&ip4, network_header_off, skb_head)) {
			emit_ip_error_event(ctx, 0, &cookie, false,
					    version, 1, 0, IP_ERROR_INET_READ_IP);
			return 0;
		}
		if (ip4.protocol != IPPROTO_ICMP)
			return 0;

		if (probe_read(&transport_header_off, sizeof(transport_header_off),
			       _(&(skb->transport_header))) < 0) {
			emit_ip_error_event(ctx, &ip4, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}
		if (probe_read(icmp_data, sizeof(icmp_data), skb_head + transport_header_off) < 0) {
			emit_ip_error_event(ctx, &ip4, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}

		val->icmp_type = icmp_data[0];
		// Don't handle Echo Reply here as it will be handled by cgroup_skb ingress.
		if (val->icmp_type == ICMP_ECHOREPLY)
			return 0;
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip4.tot_len) - (ip4.ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
		probe_read(val->icmp_data, sizeof(val->icmp_data), skb_head + transport_header_off + ICMP_HDR_LEN);

		val->tuple.saddr[0] = ip4.daddr;
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[0] = ip4.saddr;
		val->tuple.daddr[1] = 0;
		val->tuple.ipv6 = 0;
		val->tuple.proto = IPPROTO_ICMP;
		val->icmp_ip_port = 0;
		val->icmp_ip_ttl = 0;
		val->icmp_ip_pointer = 0;
		val->icmp_gateway[0] = 0;
		val->icmp_gateway[1] = 0;

		rep_ip4 = (struct iphdr *)(skb_head + transport_header_off + ICMP_HDR_LEN + sizeof(u32));
		probe_read(&val->icmp_ip_proto, sizeof(val->icmp_ip_proto), &rep_ip4->protocol);

		switch (val->icmp_type) {
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			probe_read(&val->icmp_ip_ttl, sizeof(val->icmp_ip_ttl), &rep_ip4->ttl);
			probe_read(&iv, sizeof(iv), rep_ip4);
			switch (val->icmp_ip_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP: // Note ports are in the same location in TCP and UDP headers
				tcp = (struct tcphdr *)((char *)rep_ip4 + (iv.ihl * sizeof(u32)));
				probe_read(&val->icmp_ip_port, sizeof(val->icmp_ip_port), &tcp->dest);
				val->icmp_ip_port = bpf_ntohs(val->icmp_ip_port);
				break;
			}
			break;
		}

		if (val->icmp_type == ICMP_PARAMETERPROB)
			val->icmp_ip_pointer = val->icmp_data[0];
		if (val->icmp_type == ICMP_REDIRECT) {
			val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);
		}

		send_icmp_event(ctx, val, &cookie, skb, skb_head + transport_header_off + ICMP_HDR_LEN + sizeof(u32));
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(ctx, 0, &cookie, false, version, 1, 0, IP_ERROR_INET_NO_VERSION);
		return 0;
	}
	return 0;
}
