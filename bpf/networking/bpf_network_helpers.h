static inline __attribute__((always_inline))
void get_socket_stats(struct sock *sk, struct msg_socket_stats *stats)
{
	struct tcp_sock *tcp = (struct tcp_sock *)sk;

	probe_read(&stats->bytes_sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	probe_read(&stats->bytes_received, sizeof(__u64), _(&(tcp->bytes_received)));
	probe_read(&stats->segs_in, sizeof(__u32), _(&(tcp->segs_in)));
	probe_read(&stats->segs_out, sizeof(__u32), _(&(tcp->segs_out)));
}

static inline __attribute__((always_inline))
void zero_socket_stats(struct msg_socket_stats *stats)
{
	stats->bytes_sent = 0;
	stats->bytes_received = 0;
	stats->segs_in = 0;
	stats->segs_out = 0;
}
