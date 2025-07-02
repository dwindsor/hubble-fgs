// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_EVENT_H__
#define __BPF_UDP_EVENT_H__

#include "lib/iso_msg_types.h"
#include "lib/networkmsg.h"
#include "bpf_network_helpers.h"
#include "bpf_latency.h"
#include "bpf_tracing.h"
#include "bpf_udp_info.h"
#include "../bpf_network_event_config.h"

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
} tg_h_udp_ev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} tg_h_udp_payld SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_packet_details);
	__uint(max_entries, 1);
} tg_h_udp_header SEC(".maps");

static inline __attribute__((always_inline)) struct msg_udp_event *
build_udp_payload_event(struct udp_info_key *k, struct udp_info_value *v, u64 cookie, u64 cookie_ver, u64 ps_ver, int size)
{
	struct msg_udp_event *val;
	int z = 0;

	val = (struct msg_udp_event *)map_lookup_elem(&tg_h_udp_ev, &z);
	if (!val)
		return 0;

	val->event.common.op = ISO_MSG_OP_UNDEF;
	val->event.common.size = size;
	val->event.common.ktime = tg_get_ktime();
	val->event.key.pid = v->pid;
	val->event.key.ktime = v->pid_ktime;
	val->event.tuple.ipv6 = k->tuple.ipv6;
	val->event.tuple.saddr[0] = k->tuple.saddr[0];
	val->event.tuple.saddr[1] = k->tuple.saddr[1];
	/* FGS expects host byte-order */
	val->event.tuple.sport = k->tuple.sport;
	val->event.tuple.daddr[0] = k->tuple.daddr[0];
	val->event.tuple.daddr[1] = k->tuple.daddr[1];
	val->event.tuple.dport = k->tuple.dport;
	val->event.create_time = v->create_time;
	val->event.close_time = 0;
	// WRITE_ONCE to tell compiler to use single store instead
	// of optimizing into a byte by byte store that would be
	// rejected by verifier.
	WRITE_ONCE(val->event.socket_cookie, cookie);
	val->event.version = cookie_ver;
	val->event.ps_version = ps_ver;
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_event(void *ctx, int op, u64 *cookie, u64 cookie_ver, u64 ps_ver, struct udp_info_key *k, struct udp_info_value *v)
{
	size_t size = sizeof(struct msg_ip_event);
	struct event_disable_config *event_cfg;
	struct msg_ip_event *val;
	u32 zero = 0;

	event_cfg = (struct event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return;

	val = (struct msg_ip_event *)build_udp_payload_event(k, v, *cookie, cookie_ver, ps_ver, size);
	if (!val)
		return;

	if (!event_cfg->disableConnect) {
		val->common.op = op;
		perf_event_output_metric(ctx, ISO_MSG_OP_UDPCONNECT, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	}
	return;
}

static inline __attribute__((always_inline)) struct msg_udp_event *
create_udp_payload_event(void *ctx, void *ip, u64 *cookie, u64 cookie_ver, u64 ps_ver,
			 bool ipv6, void *skb_head, struct udp_info_key *k,
			 struct udp_info_value *v, int off,
			 int payload_size, size_t *size)
{
	struct msg_udp_event *val;
	int err;

	*size = payload_size + sizeof(struct msg_ip_event) + 1;
	val = build_udp_payload_event(k, v, *cookie, cookie_ver, ps_ver, *size);
	if (!val)
		return 0;

	val->event.common.op = ISO_MSG_OP_UDPPAYLOAD;

	// Move constraint on payload_size to closer to use to stop register
	// spilling condusing the verifier.
	payload_size &= 0x7ff;
	// +1 to ensure payload_size is non-zero; And keeps verifier happy that
	// we wont do a load_bytes with size == 0.
	asm volatile(
		"%[payload_size] += 1;\n"
		: [payload_size] "+r"(payload_size));
#ifndef IS_KPROBE
	err = skb_load_bytes((struct __sk_buff *)ctx, off, &val->payload, payload_size);
#else
	err = probe_read_kernel(&val->payload, payload_size, skb_head + off);
#endif
	if (err < 0) {
		emit_ip_error_event(ctx, ip, cookie, ipv6,
				    0, 0, 0, IP_ERROR_INET_READ_PAYLOAD);
		return 0;
	}
	return val;
}

static inline __attribute__((always_inline)) void
emit_udp_payload_event(void *ctx, void *ip, u64 *cookie, u64 cookie_ver, u64 ps_ver, bool ipv6,
		       struct udp_info_key *k, struct udp_info_value *v, int off,
		       int payload_size)
{
	struct msg_udp_event *val;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, cookie_ver, ps_ver, ipv6, 0, k, v, off, payload_size, &size);
	if (!val)
		return;

	// Having moved the constraint on payload_size in create_udp_payload_event()
	// above, we now need to do it here as well.
	size &= 0x7ff;
	perf_event_output_metric(ctx, ISO_MSG_OP_UDPPAYLOAD, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void
store_udp_payload_event(void *ctx, void *ip, u64 *cookie, u64 cookie_ver, u64 ps_ver,
			bool ipv6, void *skb_head, struct udp_info_key *k,
			struct udp_info_value *v, int off, int payload_size)
{
	struct msg_udp_event *val;
	int zero = 0;
	size_t size;

	val = create_udp_payload_event(ctx, ip, cookie, cookie_ver, ps_ver, ipv6, skb_head, k, v, off,
				       payload_size, &size);
	if (!val)
		return;

	/* Store and then retrieve the payload data in order to trick the
	 * verifier into thinking it isn't skb data so that we can send it
	 * out the perf ring buffer!
	 */
	map_update_elem(&tg_h_udp_payld, &zero, val, 0);

	val = (struct msg_udp_event *)map_lookup_elem(&tg_h_udp_payld, &zero);
	if (!val)
		return;
	size &= 0x7ff;
	perf_event_output_metric(ctx, ISO_MSG_OP_UDPPAYLOAD, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
}

static inline __attribute__((always_inline)) void
emit_udp_connect_event(void *ctx, u64 *cookie, u64 cookie_ver, u64 ps_ver, struct udp_info_key *k, struct udp_info_value *v)
{
	emit_udp_event(ctx, ISO_MSG_OP_UDPCONNECT, cookie, cookie_ver, ps_ver, k, v);
}
#endif // __BPF_UDP_EVENT_H__
