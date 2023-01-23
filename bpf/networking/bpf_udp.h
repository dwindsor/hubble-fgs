#ifndef __BPF_UDP_H__
#define __BPF_UDP_H__

#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"

/* Applying 'packed' attribute to structs causes clang to write to the
 * members byte-by-byte, as offsets may not be aligned. This is bad for
 * performance, instruction count and complexity, so don't apply this
 * attribute to structs where members are correctly aligned already
 * (e.g. by padding, layout).
 */

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

/* Maximum number of simultaniously existing UDP payloads waiting for
 * process info (should be much smaller that MAX_UDP_ENDPOINTS).
 */
#define MAX_UDP_PAYLOADS 512
/* The number of buckets in the related bloom map */
#define UDP_BLOOM_BUCKETS  4096
#define UDP_BLOOM_KEY_MASK 0xFFF

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
	u64 saddr[2];
	u64 daddr[2];
	u16 sport;
	u16 dport;
	u32 skb_consume_misses;
	u8 ipv6;
	u8 padding[7];
	u64 create_time;
}; // All fields aligned so no 'packed' attribute.

struct udp_info {
	union {
		u32 ipv4;
		u64 ipv6[2];
	} saddr;
	union {
		u32 ipv4;
		u64 ipv6[2];
	} daddr;
	u16 sport;
	u16 dport;
	u8 ipv6;
	u8 padding[3];
}; // All fields aligned so no 'packed' attribute.

struct msg_udp_event {
	struct msg_ip_event event;
	char payload[2048];
};

struct udp_packet_details {
	union {
		struct iphdr ip4;
		struct ipv6hdr ip6;
	} ip;
	struct udphdr udp;
	u16 udp_off;
	int payload_sz;
	int payload_off;
	void *skb_head;
	u8 version;
	u8 protocol;
	u16 network_header_off;
	bool ipv6;
};

struct udp_sensor_config {
	u16 dnsPorts[4];
	u64 watermark_enable;
	u64 watermark_avg_window_size_ms;
	u64 watermark_window_size;
	u64 watermark_trigger_percent;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct udp_sensor_config);
	__uint(max_entries, 1);
} udp_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} udp_event_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct udp_info_value);
	__uint(max_entries, MAX_UDP_ENDPOINTS);
} udp_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_value);
	__uint(max_entries, 1);
} udp_value_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info);
	__uint(max_entries, 1);
} udp_info_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} udp_cookie_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} udp_payload_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_packet_details);
	__uint(max_entries, 1);
} udp_header_heap SEC(".maps");

struct payload_bloom_value {
	u16 data[UDP_BLOOM_BUCKETS];
};

static inline __attribute__((always_inline)) void
copy_ipv6_addrs_to_info(struct udp_info *info, struct in6_addr *saddr,
			struct in6_addr *daddr)
{
	u64 *addr;
	addr = (u64 *)saddr;
	info->saddr.ipv6[0] = addr[0];
	info->saddr.ipv6[1] = addr[1];
	addr = (u64 *)daddr;
	info->daddr.ipv6[0] = addr[0];
	info->daddr.ipv6[1] = addr[1];
}

static inline __attribute__((always_inline)) void
emit_udp_event(void *ctx, int op, struct udp_info_value *v)
{
	size_t size = sizeof(struct msg_ip_event);
	struct msg_ip_event *val;
	int zero = 0;

	val = map_lookup_elem(&udp_event_heap, &zero);
	if (!val)
		return;

	val->common.op = op;
	val->common.size = sizeof(struct msg_ip_event);
	val->common.ktime = ktime_get_ns();
	val->key.pid = v->pid;
	val->key.ktime = v->pid_ktime;
	val->tuple.ipv6 = v->ipv6;
	val->tuple.saddr[0] = v->saddr[0];
	val->tuple.saddr[1] = v->saddr[1];
	/* FGS expects host byte-order */
	val->tuple.sport = v->sport;
	val->tuple.daddr[0] = v->daddr[0];
	val->tuple.daddr[1] = v->daddr[1];
	val->tuple.dport = v->dport;
	val->stats.segs_in = v->segs_in;
	val->stats.segs_out = v->segs_out;
	val->stats.bytes_sent = v->tx_bytes;
	val->stats.bytes_received = v->rx_bytes;
	val->stats.sk_drops = v->sk_drops;
	val->stats.skb_consume_misses = v->skb_consume_misses;
	val->socket_flags = 0;
	val->pad = 0;
	val->duration = 0;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	return;
}

static inline __attribute__((always_inline)) struct msg_udp_event *
create_udp_payload_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
			 void *skb_head, struct udp_info_value *v, int off,
			 int payload_size, size_t *size, bool kp)
{
	struct __sk_buff *skb = (struct __sk_buff *)ctx;
	struct msg_udp_event *val;
	int zero = 0;

	val = map_lookup_elem(&udp_event_heap, &zero);
	if (!val)
		return 0;

	*size = payload_size + sizeof(struct msg_ip_event) + 1;

	val->event.common.op = ISO_MSG_OP_UDPPAYLOAD;
	val->event.common.size = *size;
	val->event.common.ktime = ktime_get_ns();
	val->event.key.pid = v->pid;
	val->event.key.ktime = v->pid_ktime;
	val->event.tuple.ipv6 = v->ipv6;
	val->event.tuple.saddr[0] = v->saddr[0];
	val->event.tuple.saddr[1] = v->saddr[1];
	/* FGS expects host byte-order */
	val->event.tuple.sport = v->sport;
	val->event.tuple.daddr[0] = v->daddr[0];
	val->event.tuple.daddr[1] = v->daddr[1];
	val->event.tuple.dport = v->dport;
	val->event.stats.segs_in = v->segs_in;
	val->event.stats.segs_out = v->segs_out;
	val->event.stats.bytes_sent = v->tx_bytes;
	val->event.stats.bytes_received = v->rx_bytes;
	val->event.stats.sk_drops = v->sk_drops;
	val->event.stats.skb_consume_misses = v->skb_consume_misses;
	val->event.pad = 0;
	val->event.duration = 0;

	// Move constraint on payload_size to closer to use to stop register
	// spilling condusing the verifier.
	payload_size &= 0x7ff;
	// +1 to ensure payload_size is non-zero; And keeps verifier happy that
	// we wont do a load_bytes with size == 0.
	asm volatile(
		"%[payload_size] += 1;\n" ::[payload_size] "+r"(payload_size)
		:);
	if (!kp) {
		if (skb_load_bytes(skb, off, &val->payload, payload_size) < 0) {
			emit_ip_error_event(ctx, ip, cookie, ipv6,
					    IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}
	} else {
		if (probe_read(&val->payload, payload_size, skb_head + off) <
		    0) {
			emit_ip_error_event(ctx, ip, cookie, ipv6,
					    IP_ERROR_INET_READ_PAYLOAD);
			return 0;
		}
	}
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_payload_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
		       struct udp_info_value *v, int off, int payload_size)
{
	struct msg_udp_event *val;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, ipv6, 0, v, off,
				       payload_size, &size, false);
	if (!val)
		return;

	// Having moved the constraint on payload_size in create_udp_payload_event()
	// above, we now need to do it here as well.
	size &= 0x7ff;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void
store_udp_payload_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
			void *skb_head, struct udp_info_value *v, int off,
			int payload_size, bool kp)
{
	struct msg_udp_event *val;
	int zero = 0;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, ipv6, skb_head, v, off,
				       payload_size, &size, kp);
	if (!val)
		return;

	/* Store and then retrieve the payload data in order to trick the
	 * verifier into thinking it isn't skb data so that we can send it
	 * out the perf ring buffer!
	 */
	map_update_elem(&udp_payload_map, &zero, val, 0);

	val = map_lookup_elem(&udp_payload_map, &zero);
	if (!val)
		return;
	size &= 0x7ff;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void
emit_udp_connect_event(void *ctx, struct udp_info_value *v)
{
	emit_udp_event(ctx, ISO_MSG_OP_UDPCONNECT, v);
}

static inline __attribute__((always_inline)) void
udp_info_init(struct udp_info_value *v)
{
	v->pid = 0;
	v->pid_ktime = 0;
	v->sk_drops = 0;
	v->saddr[0] = 0;
	v->saddr[1] = 0;
	/* Technically, daddr, sport and dport don't need initialising
	 * because if saddr is 0 then we know that the full tuple needs
	 * to be filled in. However, to avoid a bug where the entry is
	 * read from user space and treated as valid, even if the tuple
	 * has yet to be completed, let's initialise them all. These
	 * *_reset() functions only get called once per new socket so
	 * the additional instructions shouldn't be a big overhead.
	 */
	v->daddr[0] = 0;
	v->daddr[1] = 0;
	v->sport = 0;
	v->dport = 0;
	v->skb_consume_misses = 0;
	v->ipv6 = 0;
	WRITE_ONCE(v->ktime, ktime_get_ns());
	v->create_time = 0;
}

static inline __attribute__((always_inline)) void
udp_info_tx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = len;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = len ? 1 : 0;
	v->consumed_segs = 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
udp_info_rx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = len;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 1;
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
	udp_info_init(v);

	v->submitted_bytes = len;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = len ? 1 : 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
udp_info_consumed_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = len;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = len ? 1 : 0;
	v->segs_in = 0;
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
