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
#include "bpf_sockops.h"
#include "tls/parser.h"

#define TLS_TYPE_HELLO 22
#define TLS_TYPE_DONE 0xff

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

// hook: ./net/ipv4/tcp_ipv4.c tcp_filter()
__attribute__((section(("cgroup_skb/ingress")), used))
int bpf_cgroup_skb_ingress_tls(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct msg_tls *event;

	key.daddr = skb->remote_ip4;
	key.saddr = skb->local_ip4;
	key.dport = skb->remote_port;
	key.sport = skb->local_port;
	key.proto = 0;

	event = map_lookup_elem(&tls_map, &key);
	if (event && event->type == TLS_TYPE_HELLO)
		bpf_parse_tls_skb(skb, event);
	return 1;
}
