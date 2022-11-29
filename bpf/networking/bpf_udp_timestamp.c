#include "vmlinux.h"
#include "api.h"
#include "bpf_udp_timestamp.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("classifier/udp_egress_timestamp"), used)) int
udp_egress_timestamp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;

	if (data + sizeof(*eth) > data_end) {
		return TC_ACT_PIPE;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_IP_P) {
		return TC_ACT_PIPE;
	}

	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		return TC_ACT_PIPE;
	}

	iph = data + sizeof(*eth);
	switch (iph->version) {
	case 4:
		if (udp_egress_timestamp4(skb, data, data_end, eth, iph)) {
			return TC_ACT_PIPE;
		} else {
			return TC_ACT_SHOT;
		}
		break;
	case 6:
		if (udp_egress_timestamp6(skb, data, data_end, eth)) {
			return TC_ACT_PIPE;
		} else {
			return TC_ACT_SHOT;
		}
		break;
	default:
		emit_ip_error_event(skb, 0, 0, false, IP_ERROR_INET_NO_VERSION);
		return TC_ACT_PIPE;
	}
}
