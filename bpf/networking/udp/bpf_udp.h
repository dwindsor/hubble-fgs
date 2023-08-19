#ifndef __BPF_UDP_H__
#define __BPF_UDP_H__

#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../bpf_network_helpers.h"
#include "../bpf_latency.h"
#include "bpf_tracing.h"
#include "bpf_udp_info.h"

/* Applying 'packed' attribute to structs causes clang to write to the
 * members byte-by-byte, as offsets may not be aligned. This is bad for
 * performance, instruction count and complexity, so don't apply this
 * attribute to structs where members are correctly aligned already
 * (e.g. by padding, layout).
 */

/* Maximum number of simultaniously existing UDP payloads waiting for
 * process info (should be much smaller that MAX_UDP_ENDPOINTS).
 */
#define MAX_UDP_PAYLOADS 512

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
	struct timestamp_option ipopt;
	u16 udp_off;
	int payload_sz;
	int payload_off;
	void *skb_head;
	u8 version;
	u8 protocol;
	u16 network_header_off;
	bool ipv6;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} tg_udp_event_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tg_udp_cookie_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} tg_udp_payload_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_packet_details);
	__uint(max_entries, 1);
} tg_udp_header_heap SEC(".maps");

static inline __attribute__((always_inline)) struct msg_udp_event *
build_udp_payload_event(struct udp_info_value *v, u64 cookie, int size)
{
	struct msg_udp_event *val;
	int z = 0;

	val = (struct msg_udp_event *)map_lookup_elem(&tg_udp_event_heap, &z);
	if (!val)
		return 0;

	val->event.common.op = ISO_MSG_OP_UNDEF;
	val->event.common.size = size;
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
	// WRITE_ONCE to tell compiler to use single store instead
	// of optimizing into a byte by byte store that would be
	// rejected by verifier.
	WRITE_ONCE(val->event.socket_cookie, cookie);
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_event(void *ctx, int op, u64 *cookie, struct udp_info_value *v)
{
	size_t size = sizeof(struct msg_ip_event);
	struct msg_ip_event *val;

	val = (struct msg_ip_event *)build_udp_payload_event(v, *cookie, size);
	if (!val)
		return;
	val->common.op = op;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	return;
}

static inline __attribute__((always_inline)) struct msg_udp_event *
create_udp_payload_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
			 void *skb_head, struct udp_info_value *v, int off,
			 int payload_size, size_t *size)
{
	struct msg_udp_event *val;
	int err;

	*size = payload_size + sizeof(struct msg_ip_event) + 1;
	val = build_udp_payload_event(v, *cookie, *size);
	if (!val)
		return 0;

	val->event.common.op = ISO_MSG_OP_UDPPAYLOAD;

	// Move constraint on payload_size to closer to use to stop register
	// spilling condusing the verifier.
	payload_size &= 0x7ff;
	// +1 to ensure payload_size is non-zero; And keeps verifier happy that
	// we wont do a load_bytes with size == 0.
	asm volatile(
		"%[payload_size] += 1;\n" ::[payload_size] "+r"(payload_size)
		:);
#ifndef IS_KPROBE
	err = skb_load_bytes(ctx, off, &val->payload, payload_size);
#else
	err = probe_read(&val->payload, payload_size, skb_head + off);
#endif
	if (err < 0) {
		emit_ip_error_event(ctx, ip, cookie, ipv6,
				    0, 0, 0, IP_ERROR_INET_READ_PAYLOAD);
		return 0;
	}
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_payload_event(void *ctx, void *ip, u64 *cookie, bool ipv6,
		       struct udp_info_value *v, int off, int payload_size)
{
	struct msg_udp_event *val;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, ipv6, 0, v, off, payload_size, &size);
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
			int payload_size)
{
	struct msg_udp_event *val;
	int zero = 0;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, ipv6, skb_head, v, off,
				       payload_size, &size);
	if (!val)
		return;

	/* Store and then retrieve the payload data in order to trick the
	 * verifier into thinking it isn't skb data so that we can send it
	 * out the perf ring buffer!
	 */
	map_update_elem(&tg_udp_payload_map, &zero, val, 0);

	val = (struct msg_udp_event *)map_lookup_elem(&tg_udp_payload_map, &zero);
	if (!val)
		return;
	size &= 0x7ff;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void
emit_udp_connect_event(void *ctx, u64 *cookie, struct udp_info_value *v)
{
	emit_udp_event(ctx, ISO_MSG_OP_UDPCONNECT, cookie, v);
}
#endif // __BPF_UDP_H__
