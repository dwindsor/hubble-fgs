#include "vmlinux.h"
#include "api.h"
#include "../lib/tlsmsg.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tlsmsg.h"
#include "../../lib/iso_msg_types.h"
#include "tls_map.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct msg_tls_event);
	__uint(max_entries, 1);
} heap SEC(".maps");

#define TLS_TYPE_HELLO 22

__attribute__((section("kprobe/tcp_v4_fill_cb"), used)) int
event_ingress_tcp4(struct pt_regs *ctx)
{
	return event_ingress_tcp(ctx, false);
}

__attribute__((section("kprobe/tcp_v6_fill_cb"), used)) int
event_ingress_tcp6(struct pt_regs *ctx)
{
	return event_ingress_tcp(ctx, true);
}

static inline __attribute__((always_inline)) int
event_ingress_tcp(struct pt_regs *ctx, bool ipv6)
{
	struct msg_tls_ip tuple = { 0 };
	struct msg_tls *event;
	struct tcphdr *tcphdr;
	struct iphdr *ip4hdr;
	struct ipv6hdr *ip6hdr;
	u32 addr;
	struct sk_buff *skb;
	struct sock *sk;
	int zero = 0;
	u64 *cookie;

	ip4hdr = (void *)((ctx)->si);
	ip6hdr = (void *)((ctx)->si);
	tcphdr = (void *)((ctx)->dx);
	skb = (void *)((ctx)->di);

	probe_read(&sk, sizeof(sk), _(&(skb->sk)));
	cookie = map_lookup_elem(&tls_cookie_heap, &zero);
	if (!cookie)
		return;
	*cookie = (u64)sk;
	if (!*cookie)
		return;

	if (!ipv6) {
		probe_read(&addr, sizeof(addr), _(&(ip4hdr->daddr)));
		tuple.saddr[0] = addr;
		probe_read(&addr, sizeof(addr), _(&(ip4hdr->saddr)));
		tuple.daddr[0] = addr;
		tuple.ipv6 = 0;
	} else {
		probe_read(&tuple.saddr, sizeof(tuple.saddr),
			   _(&(ip6hdr->daddr)));
		probe_read(&tuple.daddr, sizeof(tuple.daddr),
			   _(&(ip6hdr->saddr)));
		tuple.ipv6 = 1;
	}
	probe_read(&tuple.sport, sizeof(tuple.sport), _(&(tcphdr->dest)));
	probe_read(&tuple.dport, sizeof(tuple.dport), _(&(tcphdr->source)));

	tuple.dport = 0; //bpf_htons(tuple.dport);
	tuple.sport = bpf_htons(tuple.sport);

	event = map_lookup_elem(&tls_map, cookie);
	if (event && event->type) {
		int zero = 0;
		struct msg_tls_event *post = map_lookup_elem(&heap, &zero);

		if (!post) // should not be possible
			return 0;
		post->clienthello = *event;
		post->tuple = tuple;
		post->common.op = ISO_MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
	}
	return 0;
}
