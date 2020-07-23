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
	struct msg_tls_ipv4 key = {0};
	struct msg_tls *event;
	struct tcphdr *tcp;
	int off = 0;
	__u32 addr;
	__u16 port;

	tcp = skb_tls_key(skb, &off, &key);
	if (!tcp)
		return TC_ACT_OK;

	addr = key.saddr;
	key.saddr = key.daddr;
	key.daddr = addr;

	port = key.sport;
	key.sport = key.dport;
	key.dport = port;
	key.proto = 0;

	event = map_lookup_elem(&tls_map, &key);
	if (event && event->type == TLS_TYPE_HANDSHAKE) {
		struct msg_tls_event post = {0};
		struct msg_execve_key *execve;
		void *payload;
		int err;

		post.clienthello = *event;

		payload = skb_tcp_payload(skb, tcp, &off);
		if (!payload)
			return TC_ACT_OK;
		err = bpf_parse_tls(skb, payload, off, &post.serverhello);
		if (err)
			return TC_ACT_OK;
		post.tuple = key;
		post.common.op = MSG_OP_TLS;
		post.common.size = sizeof(struct msg_tls_event);

		key.dport = bpf_htons(key.dport);
		execve  = lookup_socketmap(&key);
		if (execve)
			post.execve = *execve;
		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, &post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
	}

	return TC_ACT_OK;
}
