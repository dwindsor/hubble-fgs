#include "bpf_tcp_send_check.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct rcv_rtt_est {
	s32 rtt_us;
	u32 seq;
	u64 time;
};

__attribute__((section("kprobe/__tcp_ack_snd_check"), used))
//__attribute__((section("kprobe/tcp_rcv_established"), used))
int tcp_rcv_established(struct pt_regs *ctx)
{
	struct tcp_sock *skp = (struct tcp_sock *)((ctx)->di);
	struct tcp_send_check_sample_cfg *cfg;
	struct socketmap_value *process;
	struct rcv_rtt_est rtt;
	int zero = 0;
	u64 cookie;
	u64 tcp_mstamp, delta, delta_us;

	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	process = lookup_socketmap(&cookie);
	if (!process) {
		return 0;
	}

	probe_read(&rtt, sizeof(rtt), _(&(skp->rcv_rtt_est)));
	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(
		&tcp_send_check_sampler, &zero);
	if (!cfg) {
		return 0;
	}

	probe_read(&tcp_mstamp, sizeof(tcp_mstamp), _(&(skp->tcp_mstamp)));

	/* Test for underflow */
	if (tcp_mstamp <= rtt.time)
		return 0;
	delta = tcp_mstamp - rtt.time;

/* Mimic tcp_rcv_rtt_measure_ts here */
#define USEC_PER_SEC 1000000L
#define TCP_TS_HZ    1000
	delta_us = delta * (USEC_PER_SEC / TCP_TS_HZ);

	if (cfg->bucket00 > delta_us)
		process->buckets[0]++;
	else if (cfg->bucket01 > delta_us)
		process->buckets[1]++;
	else if (cfg->bucket10 > delta_us)
		process->buckets[2]++;
	else if (cfg->bucket25 > delta_us)
		process->buckets[3]++;
	else if (cfg->bucket50 > delta_us)
		process->buckets[4]++;
	else if (cfg->bucket75 > delta_us)
		process->buckets[5]++;
	else if (cfg->bucket90 > delta_us)
		process->buckets[6]++;
	else
		process->buckets[7]++;
	return 0;
}
