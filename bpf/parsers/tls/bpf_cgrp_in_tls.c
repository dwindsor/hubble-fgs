#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"
#include "parser.h"

#define TLS_TYPE_HELLO 22
#define TLS_TYPE_DONE  0xff

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct msg_tls_ip);
	__type(value, struct msg_tls);
	__uint(max_entries, 32000);
} tls_map SEC(".maps");

// hook: ./net/ipv4/tcp_ipv4.c tcp_filter()
__attribute__((section("cgroup_skb/ingress"), used)) int
bpf_cgroup_skb_ingress_tls(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };
	struct msg_tls *event;

	key.daddr[0] = skb->remote_ip4;
	key.saddr[0] = skb->local_ip4;
	key.ipv6 = 0;
	key.dport = skb->remote_port;
	key.sport = skb->local_port;

	event = map_lookup_elem(&tls_map, &key);
	if (event && event->type == TLS_TYPE_HELLO)
		bpf_parse_tls_skb(skb, event);
	return 1;
}
