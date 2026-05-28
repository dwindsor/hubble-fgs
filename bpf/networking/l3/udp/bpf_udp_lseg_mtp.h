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
#include "bpf_udp_mcast.h"

// We include a string here that we don't expect to be found elsewhere in the code base,
// so that we can grep for it and check if this code is included in the objects.
static char lseg_build_canary[] __attribute__((used)) = "canary:lseg_build";

// For packet sampling, we hash the first 8 bytes of the UDP payload (MTP header) as this
// contains the line ID and the sequence number. jhash distributes these fairly evenly
// across the 32 bit space.

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
		      struct udp_info_key *k, struct udp_info_value *v)
{
	u32 expected_seq_num = v->mcast_seq_num;
	struct msg_udp_seq_error_event *e;
	u32 max_seq_num = (1 << 16) - 1;
	u32 temp_seq_num = 0;
	u32 next_seq_num = 0;
	u32 line_id = 0;
	u32 seq_num = 0;
	u8 line_id_sz;
	u8 seq_num_sz;
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

	// Calculate next expected seq_num.
	next_seq_num = seq_num + 1;
	// Check for overflow (as the storage is not the same size as the value).
	if (next_seq_num > max_seq_num)
		next_seq_num = 0;

	if (seq_num == expected_seq_num) {
		// Success. This is what we were expecting. Update to next sequence number.
		v->mcast_seq_num = next_seq_num;
		return;
	} else if (old_seq_num(seq_num, expected_seq_num, max_seq_num))
		/* The datagram is behind the expected one. We don't report these as per
		 * https://github.com/orgs/isovalent/projects/16/views/6?pane=issue&itemId=19577904
		 * to reduce the number of events sent. Essentially, we only report the gap, not the
		 * out of order events, because out of order events are complex and would require
		 * additional logic. In addition, we don't change the expected sequence number.
		 */
		return;

	// Error – datagram is ahead of expected one.
	// Update the expected sequence number to the next one.
	v->mcast_seq_num = next_seq_num;

	// Create event.
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
	e->tuple = k->tuple;
	e->socket_cookie = k->cookie;
	e->application_id = MULTICAST_APP_LSEGMTP;
	e->app_specific_id = line_id;
	e->seq_num_expected = expected_seq_num;
	e->seq_num_received = seq_num;
	perf_event_output_metric(skb, ISO_MSG_OP_UDP_SEQ_ERROR, &tcpmon_map, BPF_F_CURRENT_CPU, e, sizeof(struct msg_udp_seq_error_event));
}

__attribute__((noinline)) u64
udp_sample_lseg(struct __sk_buff *skb, int payload_off, int payload_sz)
{
	u64 data;

	if (payload_sz < SAMPLE_BYTES_TO_HASH)
		return 0;

	if (skb_load_bytes(skb, payload_off, &data, sizeof(data)) < 0)
		return 0;
	return data;
}

#endif

#endif // __BPF_UDP_LSEG_MTP_H__
