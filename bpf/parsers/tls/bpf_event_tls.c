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
#include "tlsmsg.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

struct bpf_map_def __attribute__((section("maps"), used)) heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_tls_event),
	.max_entries = 1,
};

#define TLS_TYPE_HELLO 22

__attribute__((section("kprobe/tcp_v4_fill_cb"), used)) int
event_ingress_tcp(struct pt_regs *ctx)
{
	struct msg_tls_ipv4 key = { 0 };
	struct msg_tls *event;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;

	iphdr = (void *)((ctx)->si);
	tcphdr = (void *)((ctx)->dx);

	probe_read(&key.saddr, sizeof(key.saddr), _(&(iphdr->daddr)));
	probe_read(&key.daddr, sizeof(key.daddr), _(&(iphdr->saddr)));

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
		post->common.op = MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
	}
	return 0;
}
