#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"

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

__attribute__((section("kprobe/tcp_rtt_estimator"), used)) int
tcp_rtt_estimator(struct pt_regs *ctx)
{
	struct tcp_sock *skp = (struct tcp_sock *)((ctx)->di);
	struct tcp_send_check_sample_cfg *cfg;
	struct socketmap_value *process;
	u64 rtt_us = (u64)((ctx)->si);
	int zero = 0;
	u64 cookie;

	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	process = lookup_socketmap(&cookie);
	if (!process) {
		return 0;
	}

	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(
		&tcp_send_check_sampler, &zero);
	if (!cfg) {
		return 0;
	}

	if (cfg->bucket00 > rtt_us)
		process->buckets[0]++;
	else if (cfg->bucket01 > rtt_us)
		process->buckets[1]++;
	else if (cfg->bucket10 > rtt_us)
		process->buckets[2]++;
	else if (cfg->bucket25 > rtt_us)
		process->buckets[3]++;
	else if (cfg->bucket50 > rtt_us)
		process->buckets[4]++;
	else if (cfg->bucket75 > rtt_us)
		process->buckets[5]++;
	else if (cfg->bucket90 > rtt_us)
		process->buckets[6]++;
	else
		process->buckets[7]++;
	return 0;
}
