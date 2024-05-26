// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

// Copied from struct tcp_sock defined in include/linux/tcp.h
struct rcv_rtt_est {
	u32 rtt_us;
	u32 seq;
	u64 time;
};

#define FLAG_DATA_ACKED 0x04
#define FLAG_SYN_ACKED	0x10
#define FLAG_ACKED	(FLAG_DATA_ACKED | FLAG_SYN_ACKED)
#define USEC_PER_SEC	1000000L
#define TCP_TS_HZ	1000
#define INT_MAX		((int)(~0U >> 1))

__attribute__((section("kprobe/__tcp_ack_snd_check"), used)) int
tg_tcp_ack_snd_check(struct pt_regs *ctx)
{
	struct tcp_sock *skp = (struct tcp_sock *)PT_REGS_PARM1(ctx);
	struct tcp_send_check_sample_cfg *cfg;
	struct socketmap_value *process;
	struct rcv_rtt_est rtt;
	int zero = 0;
	u64 cookie;
	u64 rtt_us;

	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	process = lookup_socketmap(&cookie);
	if (!process) {
		return 0;
	}

	probe_read_kernel(&rtt, sizeof(rtt), _(&(skp->rcv_rtt_est)));
	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(
		&tg_tcp_send_check_sampler, &zero);
	if (!cfg) {
		return 0;
	}

	rtt_us = rtt.rtt_us / 8; // RTT is reported as <<3 in us

	if (rtt_us <= 0)
		return 0;

	if (cfg->bucket00 > rtt_us)
		process->rtt_buckets[0]++;
	else if (cfg->bucket01 > rtt_us)
		process->rtt_buckets[1]++;
	else if (cfg->bucket10 > rtt_us)
		process->rtt_buckets[2]++;
	else if (cfg->bucket25 > rtt_us)
		process->rtt_buckets[3]++;
	else if (cfg->bucket50 > rtt_us)
		process->rtt_buckets[4]++;
	else if (cfg->bucket75 > rtt_us)
		process->rtt_buckets[5]++;
	else if (cfg->bucket90 > rtt_us)
		process->rtt_buckets[6]++;
	else
		process->rtt_buckets[7]++;

	process->rtt_sum += rtt_us;

	return 0;
}
