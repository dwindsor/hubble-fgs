// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef BPF_TCP_RTT_H
#define BPF_TCP_RTT_H

#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"
#include "bpf_tcp_info.h"

#define FLAG_DATA_ACKED 0x04
#define FLAG_SYN_ACKED	0x10
#define FLAG_ACKED	(FLAG_DATA_ACKED | FLAG_SYN_ACKED)
#define USEC_PER_SEC	1000000L
#define TCP_TS_HZ	1000
#define INT_MAX		((int)(~0U >> 1))

static inline __attribute__((always_inline)) int
__tcp_ack_update_rtt(void *ctx, struct tcp_sock *skp, u32 flag, s64 seq_rtt_us, s64 sack_rtt_us)
{
	struct tcp_send_check_sample_cfg *cfg;
	struct tcp_options_received rx_opt;
	struct tcpsocketmap_value *socket;
	u64 tcp_time_stamp;
	s64 rtt_us = -1;
	int zero = 0;
	u64 cookie;

	/* In TCP we use the struct sock address as the socket cookie. */
	cookie = (u64)skp;

	socket = lookup_tcpsocketmap(&cookie);
	if (!socket) {
		emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_TCP_RTT_NO_SOCKET);
		return 0;
	}

	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(
		&tg_tcp_send_check_sampler, &zero);
	if (!cfg)
		return 0;

	/* Implement logic from tcp_ack_update_rtt()
	 * This has been reworked to avoid the probe_read if unnecessary,
	 * and to invert all the tests to avoid nested ifs.
	 */
	if (seq_rtt_us >= 0)
		rtt_us = seq_rtt_us;
	else if (sack_rtt_us >= 0)
		rtt_us = sack_rtt_us;
	else {
		if (probe_read(&rx_opt, sizeof(rx_opt), _(&(skp->rx_opt))) < 0) {
			emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_TCP_RTT_CANNOT_READ_RX_OPT);
			return 0;
		}
		if (!rx_opt.saw_tstamp || !rx_opt.rcv_tsecr || !(flag & FLAG_ACKED)) {
			// This is not an error per se as the kernel silently ignores this scenario.
			// If RTT values look wrong or are all 0, then maybe re-enable this error
			// message.
			// emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_TCP_RTT_NO_TIMESTAMP);
			return 0;
		}
		probe_read(&tcp_time_stamp, sizeof(tcp_time_stamp), _(&(skp->tcp_mstamp)));
		tcp_time_stamp /= (USEC_PER_SEC / TCP_TS_HZ);
		rtt_us = tcp_time_stamp - rx_opt.rcv_tsecr;
		if (rtt_us >= INT_MAX / (USEC_PER_SEC / TCP_TS_HZ)) {
			emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_TCP_RTT_DELTA_TOO_BIG);
			return 0;
		}
		if (!rtt_us)
			rtt_us = 1;
		rtt_us *= (USEC_PER_SEC / TCP_TS_HZ);
	}

	if (rtt_us == 0) {
		emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_TCP_RTT_EQUALS_ZERO);
		return 0;
	}

	if (cfg->bucket00 > rtt_us)
		socket->stats.rtt_buckets[0]++;
	else if (cfg->bucket01 > rtt_us)
		socket->stats.rtt_buckets[1]++;
	else if (cfg->bucket10 > rtt_us)
		socket->stats.rtt_buckets[2]++;
	else if (cfg->bucket25 > rtt_us)
		socket->stats.rtt_buckets[3]++;
	else if (cfg->bucket50 > rtt_us)
		socket->stats.rtt_buckets[4]++;
	else if (cfg->bucket75 > rtt_us)
		socket->stats.rtt_buckets[5]++;
	else if (cfg->bucket90 > rtt_us)
		socket->stats.rtt_buckets[6]++;
	else
		socket->stats.rtt_buckets[7]++;

	socket->stats.rtt_sum += rtt_us;

	return 0;
}

#endif
