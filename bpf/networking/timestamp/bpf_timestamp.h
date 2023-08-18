#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_latency.h"
#include "bpf_tracing.h"

#define ETH_IP_P 0x0800

/* Heap to store mangled packet prior to retransmission. PERCPU maps are limited
 * to 32768 bytes, and I'd like to use "&= (2^n -1)" construction to constrain
 * a len variable, so make the size 16384 plus the headers. In doing, we limit
 * this option to packets with a payload <16384 bytes, which should be okay.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, unsigned char[16384 + sizeof(struct ethhdr) +
				    sizeof(struct iphdr) + IPO_LEN + 1]);
	__uint(max_entries, 1);
} packet_heap SEC(".maps");

static inline __attribute__((always_inline)) bool
port_permitted(struct latency_protocol_config *config, u16 dport, u16 sport)
{
	/* If no ports specified, then all ports permitted. */
	if (config->ports[0] == 0) {
		return true;
	}
	if (config->ports[0] == sport ||
	    config->ports[0] == dport ||
	    config->ports[1] == sport ||
	    config->ports[1] == dport ||
	    config->ports[2] == sport ||
	    config->ports[2] == dport ||
	    config->ports[3] == sport ||
	    config->ports[3] == dport) {
		return true;
	}
	return false;
}

/* daddr is in network order. addr is in network order. */
static inline __attribute__((always_inline)) bool
check_subnet4(u32 addr, u8 prefix_len, u32 daddr)
{
	u32 mask = 0xffffffff >> (32 - prefix_len);
	if ((addr & mask) == (daddr & mask)) {
		return true;
	}
	return false;
}

/* daddr is in network order */
static inline __attribute__((always_inline)) bool
ip4_permitted(struct latency_protocol_config *config, u32 daddr)
{
	if (config->subnets[0].addr[0] == 0) {
		return false;
	}
	if (check_subnet4(config->subnets[0].addr[0],
			  config->subnets[0].prefix_len, daddr)) {
		return true;
	}
	if (config->subnets[1].addr[0] == 0) {
		return false;
	}
	if (check_subnet4(config->subnets[1].addr[0],
			  config->subnets[1].prefix_len, daddr)) {
		return true;
	}
	if (config->subnets[2].addr[0] == 0) {
		return false;
	}
	if (check_subnet4(config->subnets[2].addr[0],
			  config->subnets[2].prefix_len, daddr)) {
		return true;
	}
	if (config->subnets[3].addr[0] == 0) {
		return false;
	}
	if (check_subnet4(config->subnets[3].addr[0],
			  config->subnets[3].prefix_len, daddr)) {
		return true;
	}
	return false;
}

/* Return true if the packet is intact, either because it hasn't been modified,
 * or because it has been correctly modified. Return false if the packet has been
 * partially modified and then something failed.
 */
static inline __attribute__((always_inline)) bool
egress_timestamp4(struct __sk_buff *skb, void *data, void *data_end,
		  struct ethhdr *eth, struct iphdr *iph)
{
	void *buffer;
	u32 len;
	struct timestamp_option *opt;
	struct latency_config *latency_config;
	struct latency_protocol_config *config;
	struct iphdr *newiph;
	u16 source = 0;
	u16 dest = 0;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u16 tot_len;
	int zero = 0;
	long ret;
	u32 ip_csum;
	u16 *pkt_words;
	u64 timestamp;

	if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP)
		return true;

	latency_config = (struct latency_config *)map_lookup_elem(&tg_latency_config_map, &zero);
	if (!latency_config)
		return true;

	switch (iph->protocol) {
	case IPPROTO_UDP:
		config = &latency_config->udp;
		break;
	case IPPROTO_TCP:
		config = &latency_config->tcp;
		break;
	default:
		return true;
	}

	if (!config->enable)
		return true;

	if (config->maxPacketSize && ((u64)data_end - (u64)data - sizeof(*eth) + IPO_LEN > config->maxPacketSize))
		return true;

	switch (iph->protocol) {
	case IPPROTO_UDP:
		if (data + sizeof(*eth) + (iph->ihl * 4) + sizeof(*udph) > data_end)
			return true;
		udph = (struct udphdr *)(data + sizeof(*eth) + (iph->ihl * 4));
		source = udph->source;
		dest = udph->dest;
		break;
	case IPPROTO_TCP:
		if (data + sizeof(*eth) + (iph->ihl * 4) + sizeof(*tcph) > data_end)
			return true;
		tcph = (struct tcphdr *)(data + sizeof(*eth) + (iph->ihl * 4));

		// We won't add timestamps to SYN or SYN/ACK packets.
		if (tcph->syn)
			return true;

		source = tcph->source;
		dest = tcph->dest;
		break;
	}

	/* Check if port is permitted. Can be source or destination so latency can be measured
	 * in both directions.
	 */
	if (!port_permitted(config, bpf_ntohs(dest), bpf_ntohs(source))) {
		return true;
	}

	/* Check if IP is permitted. Only destination IP as source IP provides little information.
	 * Network order for ease.
	 */
	if (!ip4_permitted(config, iph->daddr)) {
		return true;
	}

	buffer = map_lookup_elem(&packet_heap, &zero);
	if (!buffer)
		return true;

	/* Copy the ethernet header and IPv4 header into the buffer. */
	if ((ret = skb_load_bytes(skb, 0, buffer,
				  sizeof(*eth) + sizeof(*iph))) < 0) {
		return true;
	}

	/* Amend both IP header len and total len. */
	tot_len = bpf_ntohs(iph->tot_len);
	newiph = (struct iphdr *)(buffer + sizeof(*eth));
	newiph->ihl += (IPO_LEN / 4);
	newiph->tot_len = bpf_ntohs(tot_len + IPO_LEN);

	/* Copy everything after the basic IPv4 header into the buffer. */
	len = tot_len - sizeof(*iph) - 1;

	/* This is an interesting construction in order to satisfy the verifier.
	 * The problem is that skb_load_bytes() cannot be given a 0 length, so our
	 * usual approach of "len &= (MAX-1)" (where MAX is a power of 2) is
	 * inadequate, as len could end up being 0. But at the same time, we can't
	 * possibly ask for more bytes than the packet has available, as that would
	 * also be terrible.
	 * 
	 * So first we subtract one when we calculate the length in the line above,
	 * then we do our usual "&= MASK" to limit the range, and then we add the
	 * one back on, in order to get back to the correct length, and also to
	 * restrict the variable to non-zero values. This seems to work on 4.19,
	 * 5.4, 5.10 and 5.15.
	 */

	len &= 16383;
	len++;

	if ((ret = skb_load_bytes(skb, sizeof(*eth) + sizeof(*iph),
				  buffer + sizeof(*eth) + sizeof(*iph) + IPO_LEN,
				  len)) < 0) {
		return true;
	}

	/* Add our timestamp IP option. */
	opt = (struct timestamp_option *)(buffer + sizeof(*eth) + sizeof(*iph));
	opt->type = IPO_TYPE;
	opt->len = IPO_LEN;
	opt->pointer = IPO_PTR;
	opt->flag = IPO_FLAG;
	opt->magic = bpf_ntohl(IPO_MAGIC_W);
	timestamp = ((ktime_get_ns() + latency_config->boot_ns) + 500) /
		    1000; // rounded microseconds
	opt->timestamp_low = bpf_ntohl(
		(timestamp & 0x7fffffff) |
		(1L
		 << 31)); // take lower 31 bits, set b31 for non-standard clock
	opt->magic2 = opt->magic;
	opt->timestamp_high = bpf_ntohl(
		(timestamp >> 31) |
		(1L << 31)); // remaining bits, set b31 for non-standard clock

	/* Calculate new IP header checksum. UDP checksum should be good. */
	ip_csum = bpf_ntohs(iph->check) ^ 0xffff; // 1's compliment
	ip_csum +=
		((IPO_LEN / 4) << 8) + IPO_LEN; // increase in len and tot_len
	pkt_words = (u16 *)opt; // pointer to new IP Option
	ip_csum += ((IPO_TYPE << 8) + IPO_LEN) +
		   ((IPO_PTR << 8) + IPO_FLAG); // will be optimised by compiler
	ip_csum += IPO_MAGIC_H1 + IPO_MAGIC_H2; // will be optimised by compiler
	ip_csum += bpf_ntohs(pkt_words[4]);
	ip_csum += bpf_ntohs(pkt_words[5]);
	ip_csum += bpf_ntohs(pkt_words[6]);
	ip_csum += bpf_ntohs(pkt_words[7]);
	ip_csum += bpf_ntohs(pkt_words[8]);
	ip_csum += bpf_ntohs(pkt_words[9]);
	ip_csum += (ip_csum >> 16); // add the upper half for 1's compliment
	ip_csum &= 0xffff; // and take the lower half
	ip_csum ^= 0xffff; // and then take the 1's compliment

	newiph->check = bpf_ntohs(ip_csum);

	/* Resize packet. */
	if ((ret = skb_adjust_room(skb, IPO_LEN, BPF_ADJ_ROOM_NET, 0)) < 0) {
		return true;
	}

	/* Resizing invalidated our pointers, so any additional direct packet access
	 * after this point will need to check access is within skb->data to
	 * skb->data_end. Also, from this point onwards, any failure will result in
	 * a broken packet, so return false on failure from here on to indicate that
	 * the packet shouldn't be transmitted.
         */

	/* Write the new packet back. */
	len &= 16383;
	if ((ret = skb_store_bytes(skb, 0, buffer,
				   sizeof(*eth) + sizeof(*iph) + IPO_LEN + len,
				   0)) < 0) {
		return false;
	}

	return true;
}

static inline __attribute__((always_inline)) bool
egress_timestamp6(struct __sk_buff *skb, void *data, void *data_end,
		  struct ethhdr *eth)
{
	return true;
}
