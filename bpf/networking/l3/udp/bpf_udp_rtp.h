// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_RTP_H__
#define __BPF_UDP_RTP_H__

#include "vmlinux.h"
#include "lib/bpf_helpers.h"
#include "lib/networkmsg.h"
#include "lib/iso_msg_types.h"
#include "bpf_network_helpers.h"
#include "bpf_cookie.h"
#include "bpf_tracing.h"
#include "l3_config.h"
#include "bpf_udp_mcast.h"
#include "jhash.h"

#define RTP_SEQNUM_OFFSET 2
#define RTP_SSRC_OFFSET	  8

// For packet sampling, we hash the first 4 bytes of the UDP payload (RTP header) as this
// contains the sequence number, and 4 bytes from offset 8 as this contains the SSRC.
// jhash distributes these fairly evenly across the 32 bit space.

// We return 0 in the case of errors. We might improve this in time.
static inline __attribute__((always_inline)) u64
get_rtp_ssrc(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
	     u64 *cookie, int payload_off, int payload_sz)
{
	u32 ssrc_id = 0;

	if (payload_sz < RTP_SSRC_OFFSET + sizeof(ssrc_id))
		return 0;

	if (skb_load_bytes(skb, payload_off + RTP_SSRC_OFFSET, &ssrc_id, sizeof(ssrc_id)) < 0) {
		emit_ip_error_event(skb, ip, cookie, ipv6,
				    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_DATA);
		return 0;
	}
	ssrc_id = bpf_ntohl(ssrc_id);
	return ssrc_id;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check_rtp(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		      u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		      struct udp_info_key *k, struct udp_info_value *v)
{
	u16 expected_seq_num = v->mcast_seq_num;
	struct msg_udp_seq_error_event *e;
	u16 next_seq_num;
	int zero = 0;
	u32 ssrc_id;
	u16 seq_num;

	if (payload_sz < RTP_SSRC_OFFSET + sizeof(ssrc_id))
		return;

	if (skb_load_bytes(skb, payload_off + RTP_SEQNUM_OFFSET, &seq_num, sizeof(seq_num)) < 0) {
		emit_ip_error_event(skb, ip, cookie, ipv6,
				    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_DATA);
		return;
	}
	seq_num = bpf_htons(seq_num);

	if (skb_load_bytes(skb, payload_off + RTP_SSRC_OFFSET, &ssrc_id, sizeof(ssrc_id)) < 0) {
		emit_ip_error_event(skb, ip, cookie, ipv6,
				    ip->version, 1, 0, IP_ERROR_UDP_SEQ_READ_PAYLOAD_DATA);
		return;
	}
	ssrc_id = bpf_htonl(ssrc_id);

	// Calculate next expected seq_num.
	next_seq_num = seq_num + 1;

	if (seq_num == expected_seq_num) {
		// Success. This is what we were expecting. Update to next sequence number.
		v->mcast_seq_num = next_seq_num;
		return;
	} else if (seq_num < expected_seq_num)
		/* The datagram is behind the expected one. We don't report these
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
	e->application_id = MULTICAST_APP_RTP;
	e->app_specific_id = ssrc_id;
	e->seq_num_expected = expected_seq_num;
	e->seq_num_received = seq_num;
	perf_event_output_metric(skb, ISO_MSG_OP_UDP_SEQ_ERROR, &tcpmon_map, BPF_F_CURRENT_CPU, e, sizeof(struct msg_udp_seq_error_event));
}

__attribute__((noinline)) u64
udp_sample_rtp(struct __sk_buff *skb, int payload_off, int payload_sz)
{
	u64 ssrc = 0;
	u64 sn = 0;
	u64 data;

	if (payload_sz < RTP_SSRC_OFFSET + sizeof(u32))
		return 0;

	if (skb_load_bytes(skb, payload_off, &sn, sizeof(u32)) < 0)
		return 0;
	if (skb_load_bytes(skb, payload_off + RTP_SSRC_OFFSET, &ssrc, sizeof(u32)) < 0)
		return 0;
	// Appeasing the verifier.
	data = (ssrc << 32) | sn;

	return data;
}

#endif // __BPF_UDP_RTP_H__
