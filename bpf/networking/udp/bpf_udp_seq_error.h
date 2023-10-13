#ifndef __BPF_UDP_SEQ_ERROR_H__
#define __BPF_UDP_SEQ_ERROR_H__

#include "vmlinux.h"
#include "../lib/bpf_helpers.h"
#include "../lib/networkmsg.h"
#include "../lib/iso_msg_types.h"
#include "cookie.h"
#include "bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u32[65537]);
	__uint(max_entries, 1);
} udp_seq_err_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_seq_error_event);
	__uint(max_entries, 1);
} udp_seq_err_event_heap SEC(".maps");

#ifdef SEQ_CHECK_ENABLED
static inline __attribute__((always_inline)) bool
old_seq_num(uint32_t datagram_sn, uint32_t expected_sn, uint32_t max_sn)
{
	int64_t dsn = datagram_sn;
	int64_t esn = expected_sn;

	// Normalise both sequence numbers as signed ints.
	if (datagram_sn > max_sn - 256) {
		dsn = dsn - max_sn + 1;
	}
	if (expected_sn > max_sn - 256) {
		esn = esn - max_sn + 1;
	}
	return dsn < esn;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check_mtp(struct __sk_buff *skb, void *skb_head, struct iphdr *ip, bool ipv6,
		      u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		      struct udp_info_value *v, struct udp_sensor_config *config)
{
#error "DO NOT COMPILE IF THIS IS ENABLED"
	u8 flags;
	u8 line_id_sz;
	u8 seq_num_sz;
	u32 line_id = 0;
	u32 seq_num = 0;
	u16 temp_line_id = 0;
	u32 temp_seq_num = 0;
	u32 expected_seq_num = 0;
	u32 next_seq_num = 0;
	u32 *seq_nums;
	int zero = 0;
	struct msg_udp_seq_error_event *e;
	u32 max_seq_num = (1 << 16) - 1;

	if (payload_sz < 6)
		return;

	/* Read the flags. */
	if (skb_load_bytes(skb, payload_off, &flags, 1) < 0) {
		emit_ip_error_event(skb, ip, cookie, ipv6,
				    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
		return;
	}

	line_id_sz = (flags >> 2) & 0x3;
	seq_num_sz = ((flags >> 1) & 0x1) + 2;

	/* Read the line_id. Do this explicitly to avoid verifier errors. */
	switch (line_id_sz) {
	case 0:
		line_id = 0x10000;
		break;
	case 1:
		if (skb_load_bytes(skb, payload_off + 1, &line_id, 1) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return;
		}
		break;
	case 2:
		if (skb_load_bytes(skb, payload_off + 1, &temp_line_id, 2) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return;
		}
		line_id = bpf_ntohs(temp_line_id);
	}

	/* Read the seq_num. Again, do this explicitly to avoid verifier errors. */
	switch (seq_num_sz) {
	case 2:
		if (skb_load_bytes(skb, payload_off + 1 + line_id_sz, &temp_seq_num, 2) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return;
		}
		seq_num = bpf_ntohl(temp_seq_num << 16);
		max_seq_num = (1 << 16) - 1;
		break;
	case 3:
		if (skb_load_bytes(skb, payload_off + 1 + line_id_sz, &temp_seq_num, 3) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return;
		}
		seq_num = bpf_ntohl(temp_seq_num << 8);
		max_seq_num = (1 << 24) - 1;
	}

	seq_nums = (u32 *)map_lookup_elem(&udp_seq_err_map, &zero);
	if (!seq_nums)
		return;

	if (line_id == 0x10000) {
		expected_seq_num = seq_nums[0x10000];
	} else {
		expected_seq_num = seq_nums[line_id & 0xffff];
	}

	// Calculate next expected seq_num.
	next_seq_num = seq_num + 1;
	// Check for overflow (as the storage is not the same size as the value).
	if (next_seq_num > max_seq_num) {
		next_seq_num = 0;
	}

	if (seq_num == expected_seq_num) {
		// Success. This is what we were expecting.
		if (line_id == 0x10000) {
			seq_nums[0x10000] = next_seq_num;
		} else {
			seq_nums[line_id & 0xffff] = next_seq_num;
		}
		return;
	} else if (old_seq_num(seq_num, expected_seq_num, max_seq_num)) {
		/* The datagram is behind the expected one. We don't report these as per
		 * https://github.com/orgs/isovalent/projects/16/views/6?pane=issue&itemId=19577904
		 * to reduce the number of events sent. Essentially, we only report the gap, not the
		 * out of order events, because out of order events are complex and would require
		 * additional logic. In addition, we don't change the expected sequence number.
		 */
		return;
	}

	// Error – datagram is ahead of expected one. Create event.
	e = (struct msg_udp_seq_error_event *)map_lookup_elem(&udp_seq_err_event_heap, &zero);
	if (!e)
		return;

	e->common.op = ISO_MSG_OP_UDP_SEQ_ERROR;
	e->common.size = sizeof(struct msg_udp_seq_error_event);
	e->common.ktime = ktime_get_ns();
	if (process) {
		e->key.pid = process->key.pid;
		e->key.ktime = process->key.ktime;
	} else {
		e->key.pid = 0;
		e->key.ktime = 0;
	}
	e->tuple.ipv6 = ipv6;
	e->tuple.saddr[0] = v->saddr[0];
	e->tuple.saddr[1] = v->saddr[1];
	/* FGS expects host byte-order */
	e->tuple.sport = v->sport;
	e->tuple.daddr[0] = v->daddr[0];
	e->tuple.daddr[1] = v->daddr[1];
	e->tuple.dport = v->dport;
	e->tuple.proto = IPPROTO_UDP;
	e->socket_cookie = *cookie;
	e->application_id = UDPSEQERR_APP_MTP;
	e->app_specific_id = line_id;
	e->seq_num_expected = expected_seq_num;
	e->seq_num_received = seq_num;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, e, sizeof(struct msg_udp_seq_error_event));

	// Update the expected sequence number to the next one.
	if (line_id == 0x10000) {
		seq_nums[0x10000] = next_seq_num;
	} else {
		seq_nums[line_id & 0xffff] = next_seq_num;
	}
}
#endif

static inline __attribute__((always_inline)) bool
match_seq_check_ports(u16 *ports, uint16_t port1, uint16_t port2)
{
	int i;
#pragma unroll
	for (i = 0; i < 8; i++) {
		if (!ports[i])
			return false;
		if (ports[i] == port1 || ports[i] == port2)
			return true;
	}
	return false;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check(struct __sk_buff *skb, void *skb_head, struct iphdr *ip, bool ipv6,
		  u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		  struct udp_info_value *v)
{
#ifndef IS_KPROBE
	struct udp_sensor_config *config = get_udp_config();

	if (!config || !config->seq_check_app_id)
		return;

	if (!match_seq_check_ports(config->seq_check_ports, v->sport, bpf_ntohs(v->dport)))
		return;

	switch (config->seq_check_app_id) {
#ifdef SEQ_CHECK_ENABLED
#error "DO NOT COMPILE IF THIS IS ENABLED"
	case UDPSEQERR_APP_MTP:
		udp_seq_err_check_mtp(skb, skb_head, ip, ipv6, cookie,
				      payload_off, payload_sz, process, v, config);
		return;
#endif
	}
#endif
}

#endif // __BPF_UDP_SEQ_ERROR_H__
