// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_LSEG_MTP_H__
#define __BPF_UDP_LSEG_MTP_H__

#ifdef LSEG

#include "vmlinux.h"
#include "lib/bpf_helpers.h"
#include "lib/networkmsg.h"
#include "lib/iso_msg_types.h"
#include "bpf_network_helpers.h"
#include "bpf_cookie.h"
#include "bpf_tracing.h"
#include "config.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u32[65537]);
	__uint(max_entries, 1);
} tg_l3_udp_lsegm SEC(".maps");

// We include a string here that we don't expect to be found elsewhere in the code base,
// so that we can grep for it and check if this code is included in the objects.
static char lseg_build_canary[] __attribute__((used)) = "canary:lseg_build";

static inline __attribute__((always_inline)) bool
old_seq_num(uint32_t datagram_sn, uint32_t expected_sn, uint32_t max_sn)
{
	int64_t dsn = datagram_sn;
	int64_t esn = expected_sn;

	// Normalise both sequence numbers as signed ints.
	if (datagram_sn > max_sn - 256)
		dsn = dsn - max_sn + 1;
	if (expected_sn > max_sn - 256)
		esn = esn - max_sn + 1;
	return dsn < esn;
}

static inline __attribute__((always_inline)) int
get_lseg_mtp_format(u8 *line_id_sz, u8 *seq_num_sz,
		    struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		    u64 *cookie, int payload_off, int payload_sz)
{
	u8 flags;

	if (payload_sz < 1)
		return -1;

	/* Read the flags. */
	if (skb_load_bytes(skb, payload_off, &flags, 1) < 0) {
		emit_ip_error_event(skb, ip, cookie, ipv6,
				    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
		return -2;
	}

	*line_id_sz = (flags >> 2) & 0x3;
	*seq_num_sz = ((flags >> 1) & 0x1) + 2;
	return 0;
}

// We return 0 in the case of errors. We might improve this in time.
static inline __attribute__((always_inline)) u64
get_lseg_mtp_line_id(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		     u64 *cookie, int payload_off, int payload_sz, u8 line_id_sz)
{
	u16 temp_line_id = 0;
	u32 line_id = 0;

	if (payload_sz < 1 + line_id_sz)
		return 0;

	/* Read the line_id. Do this explicitly to avoid verifier errors. */
	switch (line_id_sz) {
	case 0:
		line_id = 0x10000;
		break;
	case 1:
		if (skb_load_bytes(skb, payload_off + 1, &line_id, 1) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return 0;
		}
		break;
	case 2:
		if (skb_load_bytes(skb, payload_off + 1, &temp_line_id, 2) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_FLAGS);
			return 0;
		}
		line_id = bpf_ntohs(temp_line_id);
	}

	return line_id;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check_mtp(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		      u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		      struct udp_info_key *k)
{
	struct msg_udp_seq_error_event *e;
	u32 max_seq_num = (1 << 16) - 1;
	u32 expected_seq_num = 0;
	u32 temp_seq_num = 0;
	u32 next_seq_num = 0;
	u32 line_id = 0;
	u32 seq_num = 0;
	u8 line_id_sz;
	u8 seq_num_sz;
	u32 *seq_nums;
	int zero = 0;

	if (payload_sz < 6)
		return;

	if (get_lseg_mtp_format(&line_id_sz, &seq_num_sz, skb, ip, ipv6, cookie, payload_off, payload_sz) < 0)
		return;

	line_id = get_lseg_mtp_line_id(skb, ip, ipv6, cookie, payload_off, payload_sz, line_id_sz);

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

	seq_nums = (u32 *)map_lookup_elem(&tg_l3_udp_lsegm, &zero);
	if (!seq_nums)
		return;

	if (line_id == 0x10000)
		expected_seq_num = seq_nums[0x10000];
	else
		expected_seq_num = seq_nums[line_id & 0xffff];

	// Calculate next expected seq_num.
	next_seq_num = seq_num + 1;
	// Check for overflow (as the storage is not the same size as the value).
	if (next_seq_num > max_seq_num)
		next_seq_num = 0;

	if (seq_num == expected_seq_num) {
		// Success. This is what we were expecting.
		if (line_id == 0x10000)
			seq_nums[0x10000] = next_seq_num;
		else
			seq_nums[line_id & 0xffff] = next_seq_num;
		return;
	} else if (old_seq_num(seq_num, expected_seq_num, max_seq_num))
		/* The datagram is behind the expected one. We don't report these as per
		 * https://github.com/orgs/isovalent/projects/16/views/6?pane=issue&itemId=19577904
		 * to reduce the number of events sent. Essentially, we only report the gap, not the
		 * out of order events, because out of order events are complex and would require
		 * additional logic. In addition, we don't change the expected sequence number.
		 */
		return;

	// Error – datagram is ahead of expected one. Create event.
	e = (struct msg_udp_seq_error_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!e)
		return;

	e->common.op = ISO_MSG_OP_UDP_SEQ_ERROR;
	e->common.size = sizeof(struct msg_udp_seq_error_event);
	e->common.ktime = tg_get_ktime();
	if (process) {
		e->key.pid = process->key.pid;
		e->key.ktime = process->key.ktime;
	} else {
		e->key.pid = 0;
		e->key.ktime = 0;
	}
	e->tuple.ipv6 = ipv6;
	e->tuple.saddr[0] = k->tuple.saddr[0];
	e->tuple.saddr[1] = k->tuple.saddr[1];
	/* FGS expects host byte-order */
	e->tuple.sport = k->tuple.sport;
	e->tuple.daddr[0] = k->tuple.daddr[0];
	e->tuple.daddr[1] = k->tuple.daddr[1];
	e->tuple.dport = k->tuple.dport;
	e->tuple.proto = IPPROTO_UDP;
	e->tuple.conn_id = 0;
	e->socket_cookie = *cookie;
	e->application_id = MULTICAST_APP_LSEGMTP;
	e->app_specific_id = line_id;
	e->seq_num_expected = expected_seq_num;
	e->seq_num_received = seq_num;
	perf_event_output_metric(skb, ISO_MSG_OP_UDP_SEQ_ERROR, &tcpmon_map, BPF_F_CURRENT_CPU, e, sizeof(struct msg_udp_seq_error_event));

	// Update the expected sequence number to the next one.
	if (line_id == 0x10000)
		seq_nums[0x10000] = next_seq_num;
	else
		seq_nums[line_id & 0xffff] = next_seq_num;
}
#endif

#endif // __BPF_UDP_LSEG_MTP_H__
