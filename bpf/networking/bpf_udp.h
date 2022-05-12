#ifndef __BPF_UDP_H__
#define __BPF_UDP_H__

#include "../lib/bpf_helpers.h"
#include "../lib/networkmsg.h"

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

/* Maximum number of simultaniously existing UDP payloads waiting for
 * process info (should be much smaller that MAX_UDP_ENDPOINTS).
 */
#define MAX_UDP_PAYLOADS 512

struct udp_info_value {
	u64 submitted_bytes;
	u64 tx_bytes;
	u64 consumed_bytes;
	u64 rx_bytes;
	u64 consumed_segs;
	u64 segs_in;
	u64 submitted_segs;
	u64 segs_out;
	u64 ktime;
	u64 pid_ktime;
	u32 pid;
	u32 sk_drops;
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 skb_consume_misses;
} __attribute__((packed));

struct udp_info {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 padding;
} __attribute__((packed));

struct msg_ipv4_udp_event {
	struct msg_ipv4_event event;
	char payload[2048];
};

struct udp_packet_details {
	struct iphdr ip;
	struct udphdr udp;
	int payload_sz;
	int payload_off;
	void *skb_head;
};

struct udp_sensor_config {
	u16 dnsPorts[4];
	u64 watermark_enable;
	u64 watermark_avg_window_size_ms;
	u64 watermark_window_size;
	u64 watermark_trigger_percent;
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_sensor_config),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_event_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_ipv4_udp_event),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct udp_info_value),
	.max_entries = MAX_UDP_ENDPOINTS,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_value_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_info_value),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_info_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_info),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_cookie_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u64),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_payload_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct msg_ipv4_udp_event),
	.max_entries = MAX_UDP_PAYLOADS,
};

struct bpf_map_def __attribute__((section("maps"), used))
udp_payload_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_header_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_packet_details),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) void
emit_udp_event(void *ctx, int op, struct udp_info_value *v)
{
	size_t size = sizeof(struct msg_ipv4_event);
	struct msg_ipv4_event *val;
	int zero = 0;

	val = map_lookup_elem(&udp_event_heap, &zero);
	if (!val)
		return;

	*val = (struct msg_ipv4_event){
		.common.op = op,
		.common.size = sizeof(struct msg_ipv4_event),
		.common.ktime = ktime_get_ns(),
		.key.pid = v->pid,
		.key.ktime = v->pid_ktime,
		.tuple.saddr = v->saddr,
		/* FGS expects host byte-order */
		.tuple.sport = v->sport,
		.tuple.daddr = v->daddr,
		.tuple.dport = v->dport,
		.stats.segs_in = v->segs_in,
		.stats.segs_out = v->segs_out,
		.stats.bytes_sent = v->tx_bytes,
		.stats.bytes_received = v->rx_bytes,
		.stats.sk_drops = v->sk_drops,
		.stats.skb_consume_misses = v->skb_consume_misses,
		.socket_flags = 0,
		.pad = 0,
	};
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	return;
}

static inline __attribute__((always_inline)) struct msg_ipv4_udp_event *
create_udp_payload_event(void *ctx, void *skb_head, struct udp_info_value *v,
			 int off, int payload_size, size_t *size, bool kp)
{
	struct __sk_buff *skb = (struct __sk_buff *)ctx;
	struct msg_ipv4_udp_event *val;
	int zero = 0;

	val = map_lookup_elem(&udp_event_heap, &zero);
	if (!val)
		return 0;

	payload_size &= 0x7ff;
	*size = payload_size + sizeof(struct msg_ipv4_event) + 1;

	val->event = (struct msg_ipv4_event){
		.common.op = MSG_OP_IPV4_UDPPAYLOAD,
		.common.size = *size,
		.common.ktime = ktime_get_ns(),
		.key.pid = v->pid,
		.key.ktime = v->pid_ktime,
		.tuple.saddr = v->saddr,
		/* FGS expects host byte-order */
		.tuple.sport = v->sport,
		.tuple.daddr = v->daddr,
		.tuple.dport = v->dport,
		.stats.segs_in = v->segs_in,
		.stats.segs_out = v->segs_out,
		.stats.bytes_sent = v->tx_bytes,
		.stats.bytes_received = v->rx_bytes,
		.stats.sk_drops = v->sk_drops,
		.stats.skb_consume_misses = v->skb_consume_misses,
	};

	// +1 to ensure payload_size is non-zero; And keeps verifier happy that
	// we wont do a load_bytes with size == 0.
	asm volatile(
		"%[payload_size] += 1;\n" ::[payload_size] "+r"(payload_size)
		:);
	if (!kp) {
		skb_load_bytes(skb, off, &val->payload, payload_size);
	} else {
		if (probe_read(&val->payload, payload_size, skb_head + off) < 0)
			return 0;
	}
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_payload_event(void *ctx, struct udp_info_value *v, int off,
		       int payload_size)
{
	struct msg_ipv4_udp_event *val;
	size_t size;

	val = create_udp_payload_event(ctx, 0, v, off, payload_size, &size,
				       false);
	if (!val)
		return;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void inc_udp_payload_map()
{
	u64 *cntr;
	int zero = 0;

	cntr = map_lookup_elem(&udp_payload_map_stats, &zero);
	if (!cntr)
		return;
	*cntr = *cntr + 1;
}

static inline __attribute__((always_inline)) void dec_udp_payload_map()
{
	u64 *cntr;
	int zero = 0;

	cntr = map_lookup_elem(&udp_payload_map_stats, &zero);
	if (!cntr)
		return;
	*cntr = *cntr - 1;
}

static inline __attribute__((always_inline)) void
store_udp_payload_event(void *ctx, void *skb_head, u64 *cookie,
			struct udp_info_value *v, int off, int payload_size,
			bool kp)
{
	struct msg_ipv4_udp_event *val;
	size_t size;

	val = create_udp_payload_event(ctx, skb_head, v, off, payload_size,
				       &size, kp);
	if (!val)
		return;

	if (map_update_elem(&udp_payload_map, cookie, val, 0) == 0) {
		inc_udp_payload_map();
	}
}

static inline __attribute__((always_inline)) void
emit_udp_connect_event(void *ctx, struct udp_info_value *v)
{
	emit_udp_event(ctx, MSG_OP_IPV4_UDPCONNECT, v);
}

static inline __attribute__((always_inline)) void
udp_info_tx_reset(struct udp_info_value *v, int len)
{
	v->submitted_bytes = 0;
	v->tx_bytes = len;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = len ? 1 : 0;
	v->consumed_segs = 0;
	v->segs_in = 0;

	v->ktime = ktime_get_ns();
}

static inline __attribute__((always_inline)) void
udp_info_rx_reset(struct udp_info_value *v, int len)
{
	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = len;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 1;

	v->ktime = ktime_get_ns();
}

static inline __attribute__((always_inline)) void
update_tx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->tx_bytes, len);
	__sync_fetch_and_add(&v->segs_out, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_rx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->rx_bytes, len);
	__sync_fetch_and_add(&v->segs_in, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
udp_info_submitted_reset(struct udp_info_value *v, int len)
{
	v->submitted_bytes = len;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = len ? 1 : 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 0;

	v->ktime = ktime_get_ns();
}

static inline __attribute__((always_inline)) void
udp_info_consumed_reset(struct udp_info_value *v, int len)
{
	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = len;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = len ? 1 : 0;
	v->segs_in = 0;

	v->ktime = ktime_get_ns();
}

static inline __attribute__((always_inline)) void
update_submitted_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->submitted_bytes, len);
	__sync_fetch_and_add(&v->submitted_segs, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_consumed_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->consumed_bytes, len);
	__sync_fetch_and_add(&v->consumed_segs, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_consume_misses(struct udp_info_value *v)
{
	__sync_fetch_and_add(&v->skb_consume_misses, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) int
dns_port_match(u16 *ports, u16 port1, u16 port2)
{
	if (ports[0] == port1 || ports[0] == port2 || ports[1] == port1 ||
	    ports[1] == port2 || ports[2] == port1 || ports[2] == port2 ||
	    ports[3] == port1 || ports[3] == port2) {
		return 1;
	}
	return 0;
}

#endif // __BPF_UDP_H__
