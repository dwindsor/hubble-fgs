#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_events.h"
#include "parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

#define TLS_TYPE_HELLO 22
#define ETH_P_IP 0x800

__attribute__((section(("tc/ingress_tcp")), used))
int event_tc_ingress_tcp(struct __sk_buff *skb)
{
	void *data_end, *data;
	struct msg_tls_ipv4 key = {0};
	struct msg_tls *event;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	__u8 tcp_off;
	__u16 proto;

	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	eth = data;
	iphdr = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_OK;

	proto = eth->h_proto;
	if (proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	if (iphdr->protocol != 6)
		return TC_ACT_OK;

	key.daddr = iphdr->saddr;
	key.saddr = iphdr->daddr;
	key.proto = 0;

	tcp_off = iphdr->ihl;
	tcp_off &= 0x0f;
	tcp_off *= 4;
	tcphdr = (void *)iphdr + tcp_off;
	if ((void *)tcphdr + sizeof(struct tcphdr) > data_end) {
		int err = skb_pull_data(skb, sizeof(struct ethhdr) + tcp_off + sizeof(struct tcphdr));

		if (err)
			return TC_ACT_OK;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		tcphdr = data + sizeof(struct ethhdr) + tcp_off;
		if ((void *)tcphdr + sizeof(struct tcphdr) > data_end)
			return TC_ACT_OK;
	}

	key.dport = bpf_htons(tcphdr->source);
	key.sport = bpf_htons(tcphdr->dest);

	event = map_lookup_elem(&tls_map, &key);
	if (event && event->type) {
		struct msg_tls_event post = {0};

		post.tls = *event;
		post.tuple = key;
		post.common.op = MSG_OP_TLS;
		post.common.size = sizeof(struct msg_tls_event);

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, &post, sizeof(struct msg_tls_event));
		event->type = 0;
	}

	return TC_ACT_OK;
}
