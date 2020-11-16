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
#include "tls_map.h"
#include "parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_tls_event),
	.max_entries = 1,
};

struct nat_entry {
	__u64 created;
	__u64 host_local;	/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic. */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic. */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct bpf_map_def __attribute__((section("maps"), used)) cilium_snat_v4_external = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.key_size	= sizeof(struct ipv4_ct_tuple),
	.value_size	= sizeof(struct ipv4_nat_entry),
	.max_entries	= 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) tls_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= 1,
};

#define TLS_TYPE_HELLO 22
#define ETH_P_IP 0x800

__attribute__((section(("tc/ingress_tcp")), used))
int event_tc_ingress_tcp(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct ipv4_nat_entry *nat;
	struct ipv4_ct_tuple ct = {0};
	struct msg_tls *event;
	struct tcphdr *tcp;
	int off = 0;
	__u32 addr;
	__u16 port;

	tcp = skb_tls_key(skb, &off, &key);
	if (!tcp)
		return TC_ACT_UNSPEC;

	/* Egress hook runs in-front of Cilium SNAT, so it used same IP addr pairs
	 * as seen by socket. But, ingress hook is also running in front Cilium
	 * SNAT so the TCP key is before NAT and needs to be translated using
	 * the BPF map.
	 */
	ct.daddr = key.daddr;
	ct.saddr = key.saddr;
	ct.dport = bpf_htons(key.dport);
	ct.sport = bpf_htons(key.sport);
	ct.nexthdr = IPPROTO_TCP;
	ct.flags = 1;

	nat = map_lookup_elem(&cilium_snat_v4_external, &ct);
	if (nat) {
		key.daddr = nat->to_daddr;
		key.dport = bpf_ntohs(nat->to_dport);
	}

	/* Swap key to match egress side */
	addr = key.saddr;
	key.saddr = key.daddr;
	key.daddr = addr;

	port = key.sport;
	key.sport = key.dport;
	key.dport = port;
	key.proto = 0;

	event = map_lookup_elem(&tls_map, &key);
	if (!event)
		return TC_ACT_UNSPEC;

	if (is_expected_tls_client_hello(event)) {
		struct msg_execve_key *execve;
		struct msg_tls_event *post;
		const int zero = 0;
		void *payload;
		int next;

		post = map_lookup_elem(&heap, &zero);
		if (!post)
			return TC_ACT_UNSPEC;

		post->clienthello = *event;
		memset(&post->serverhello, 0, sizeof(post->serverhello));

		payload = skb_tcp_payload(skb, tcp, &off);
		if (!payload)
			return TC_ACT_UNSPEC;
		next = bpf_parse_tls(skb, payload, off, &post->serverhello);
		if (next < 0)
			return TC_ACT_UNSPEC;

		if (!is_expected_tls_server_hello(&post->serverhello))
			return TC_ACT_UNSPEC;

		/* If this there is a next pointer and it is TLSv1.2 lets assume
		 * its the cert and push it to user space.
		 */
		if (!(post->serverhello.flags & TLS_VERSION))
			post->serverhello.flags |= TLS_CERT;

		post->tuple = key;
		post->common.op = MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = ktime_get_ns();

		key.dport = bpf_htons(key.dport);
		execve  = lookup_socketmap(&key);
		if (execve)
			post->execve = *execve;

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;

		if (!(post->serverhello.flags & TLS_VERSION)) {
			next += off;
			event->bytes = bpf_skskb_post_cert(skb, event, next);
			if (event->bytes)
				event->type = TLS_TYPE_MORE_DATA;
		}
	} else if (is_expected_tls_data(event)) {
		tail_call(skb, &tls_calls, 0);
	}
	return TC_ACT_UNSPEC;
}


__attribute__((section(("tc/0")), used))
int event_tc_ingress_tls_data(struct __sk_buff *skb)
{
	struct msg_execve_key *execve;
	struct msg_tls_ipv4 key = {0};
	struct msg_tls_event *post;
	struct msg_tls *event;
	struct tcphdr *tcp;
	void *payload;
	int zero = 0, off = 0;
	__u32 addr;
	__u16 port;

	tcp = skb_tls_key(skb, &off, &key);
	if (!tcp)
		return TC_ACT_UNSPEC;

	/* Swap key to match egress side */
	addr = key.saddr;
	key.saddr = key.daddr;
	key.daddr = addr;

	port = key.sport;
	key.sport = key.dport;
	key.dport = port;
	key.proto = 0;

	post = map_lookup_elem(&heap, &zero);
	if (!post)
		return TC_ACT_UNSPEC;

	payload = skb_tcp_payload(skb, tcp, &off);
	if (!payload)
		return TC_ACT_UNSPEC;

	event = map_lookup_elem(&tls_map, &key);
	if (!event)
		return TC_ACT_UNSPEC;

	memset(&post->serverhello, 0, sizeof(post->serverhello));

	post->tuple = key;
	post->common.op = MSG_OP_TLS;
	post->common.size = sizeof(struct msg_tls_event);
	post->common.ktime = ktime_get_ns();
	post->serverhello.flags |= TLS_CERT;

	key.dport = bpf_htons(key.dport);
	execve  = lookup_socketmap(&key);
	if (execve)
		post->execve = *execve;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
			  sizeof(struct msg_tls_event));
	event->bytes = bpf_skskb_post_more_cert(skb, event, off, event->bytes);
	return TC_ACT_UNSPEC;
}

