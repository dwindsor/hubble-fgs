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

static inline __attribute__((always_inline)) bool
get_ip_headers(void *network_header, void *transport_header,
	       u32 network_header_size, u32 transport_header_size,
	       struct sk_buff *skb)
{
	u16 transport_header_off, network_header_off;
	void *skb_head;

	if (probe_read(&transport_header_off, sizeof(u16),
		       _(&skb->transport_header)) < 0)
		return false;
	if (probe_read(&network_header_off, sizeof(u16),
		       _(&skb->network_header)) < 0)
		return false;

	if (probe_read(&skb_head, sizeof(void *), _(&skb->head)) < 0)
		return false;
	if (probe_read(network_header, network_header_size,
		       skb_head + network_header_off) < 0)
		return false;
	if (probe_read(transport_header, transport_header_size,
		       skb_head + transport_header_off) < 0)
		return false;
	return true;
}

static inline __attribute__((always_inline)) bool
get_ip4_headers(struct iphdr *ip4_header, void *transport_header,
		u32 transport_header_size, struct sk_buff *skb)
{
	return get_ip_headers((void *)ip4_header, transport_header,
			      sizeof(struct iphdr), transport_header_size, skb);
}

static inline __attribute__((always_inline)) bool
get_udp4_headers(struct iphdr *ip4_header, struct udphdr *udp_header,
		 struct sk_buff *skb)
{
	return get_ip4_headers((void *)ip4_header, (void *)udp_header,
			       sizeof(struct udphdr), skb);
}
