#ifndef __BPF_UDP_H__
#define __BPF_UDP_H__

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

struct udp_info_value {
	u64 tx_bytes;
	u64 rx_bytes;
	u64 segs_in;
	u64 segs_out;
	u32 pid;
	u32 sk_drops;
	u64 ktime;
} __attribute__((packed));

struct udp_info_key {
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 sport;
	/* socket cookie is necessary because multiple sockets may be
	 * sending to the same tuple and we want to be sure we attribute
	 * the traffic to the correct socket and process.
	 */
	u64 cookie;
} __attribute__((packed));


struct bpf_map_def __attribute__((section("maps"), used)) udp_event_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_ipv4_event),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udp_info_key),
	.value_size = sizeof(struct udp_info_value),
	.max_entries = MAX_UDP_ENDPOINTS,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_value_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_info_value),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_key_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_info_key),
	.max_entries = 1,
};

static inline __attribute__((always_inline))
void emit_udp_event(void *ctx, int op, struct udp_info_key *k, struct udp_info_value *v)
{
	size_t size = sizeof(struct msg_ipv4_event);
	struct msg_ipv4_event *val;
	int zero = 0;

	val = map_lookup_elem(&udp_event_heap, &zero);
	if (!val)
		return;

	*val = (struct msg_ipv4_event) {
		.common.op = op,
		.common.size = sizeof(struct msg_ipv4_event),
		.common.ktime = ktime_get_ns(),
		.key.pid = v->pid,
		.key.ktime = v->ktime,
		.tuple.saddr = k->saddr,
		/* FGS expects host byte-order */
		.tuple.sport = k->sport,
		.tuple.daddr = k->daddr,
		.tuple.dport = k->dport,
		.stats.segs_in = v->segs_in,
		.stats.segs_out = v->segs_out,
		.stats.bytes_sent = v->tx_bytes,
		.stats.bytes_received = v->rx_bytes,
		.stats.sk_drops = v->sk_drops,
	};
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	return;
}

static inline __attribute__((always_inline))
void emit_udp_connect_event(void *ctx, struct udp_info_key *k, struct udp_info_value *v)
{
	emit_udp_event(ctx, MSG_OP_IPV4_UDPCONNECT, k, v);
}
#endif // __BPF_UDP_H__
