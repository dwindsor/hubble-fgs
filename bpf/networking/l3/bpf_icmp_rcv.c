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
	u16 network_header_off;
	struct iphdr ip4;
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

		if (!get_transport_header((void *)icmp_data, sizeof(icmp_data),
					  0, skb_head, skb, false)) {
			emit_ip_error_event(ctx, &ip4, &cookie, false, version, 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}

		val->icmp_type = icmp_data[0];
		// Don't handle Echo Reply here as it will be handled by cgroup_skb ingress.
		if (val->icmp_type == ICMP_ECHOREPLY)
			return 0;
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip4.tot_len) - (ip4.ihl * 4) - ICMP_HDR_LEN; // total len - IP header - ICMP header
		*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

		val->tuple.saddr[0] = ip4.daddr;
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[0] = ip4.saddr;
		val->tuple.daddr[1] = 0;
		val->tuple.ipv6 = 0;
		val->tuple.proto = IPPROTO_ICMP;
		send_icmp_event(ctx, val, &cookie);
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(ctx, 0, &cookie, false, version, 1, 0, IP_ERROR_INET_NO_VERSION);
		return 0;
	}
	return 0;
}
