static inline __attribute__((always_inline)) void
get_socket_stats(struct sock *sk, struct net *net, __u32 zerowin,
		 struct msg_socket_stats *stats)
{
	struct tcp_sock *tcp = (struct tcp_sock *)sk;

	/* Older kernels will not have these statistics. To get a full set of
	 * stats run 4.19 or higher.
	 */
	if (bpf_core_field_exists(tcp->bytes_sent))
		probe_read(&stats->bytes_sent, sizeof(__u64),
			   _(&(tcp->bytes_sent)));
	if (bpf_core_field_exists(tcp->segs_out))
		probe_read(&stats->segs_out, sizeof(__u32),
			   _(&(tcp->segs_out)));
	if (bpf_core_field_exists(tcp->bytes_retrans))
		probe_read(&stats->retransbytes, sizeof(__u64),
			   _(&(tcp->bytes_retrans)));
	if (bpf_core_field_exists(sk->sk_drops))
		probe_read(&stats->sk_drops, sizeof(__u32), _(&(sk->sk_drops)));

	/* These statistics are known to exist back to 4.12 kernels.
	 */
	probe_read(&stats->bytes_received, sizeof(__u64),
		   _(&(tcp->bytes_received)));
	probe_read(&stats->segs_in, sizeof(__u32), _(&(tcp->segs_in)));
	probe_read(&stats->srtt, sizeof(__u32), _(&(tcp->srtt_us)));
	probe_read(&stats->retranssegs, sizeof(__u32),
		   _(&(tcp->total_retrans)));

	//stats->tozerowin populated in-band TCP hook watching for zero window
	stats->tozerowin = zerowin;
}

static inline __attribute__((always_inline)) void
zero_socket_stats(struct msg_socket_stats *stats)
{
	stats->bytes_sent = 0;
	stats->bytes_received = 0;
	stats->segs_in = 0;
	stats->segs_out = 0;
}
