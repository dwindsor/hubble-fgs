#include "vmlinux.h"
#include "api.h"
#include "../lib/tlsmsg.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "tlsmsg.h"
#include "../../lib/iso_msg_types.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct msg_tls_ip);
	__type(value, struct msg_tls);
	__uint(max_entries, 32000);
} tls_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct msg_tls_event);
	__uint(max_entries, 1);
} heap SEC(".maps");

#define TLS_TYPE_HELLO 22

__attribute__((section("kprobe/tcp_v4_fill_cb"), used)) int
event_ingress_tcp(struct pt_regs *ctx)
{
	struct msg_tls_ip key = { 0 };
	struct msg_tls *event;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;
	u32 addr;

	iphdr = (void *)((ctx)->si);
	tcphdr = (void *)((ctx)->dx);

	probe_read(&addr, sizeof(addr), _(&(iphdr->daddr)));
	key.saddr[0] = addr;
	probe_read(&addr, sizeof(addr), _(&(iphdr->saddr)));
	key.daddr[0] = addr;
	key.ipv6 = 0;

	probe_read(&key.sport, sizeof(key.sport), _(&(tcphdr->dest)));
	probe_read(&key.dport, sizeof(key.dport), _(&(tcphdr->source)));

	key.dport = 0; //bpf_htons(key.dport);
	key.sport = bpf_htons(key.sport);

	event = map_lookup_elem(&tls_map, &key);
	if (event && event->type) {
		int zero = 0;
		struct msg_tls_event *post = map_lookup_elem(&heap, &zero);

		if (!post) // should not be possible
			return 0;
		post->clienthello = *event;
		post->tuple = key;
		post->common.op = ISO_MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
	}
	return 0;
}
