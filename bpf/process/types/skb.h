#ifndef __SKB_H__
#define __SKB_H__

struct skb_type {
	__u32 hash;
	__u32 len;
	__u32 priority;
	__u32 mark;
	__u32 saddr;
	__u32 daddr;
	__u32 sport;
	__u32 dport;
	__u32 proto;
};

/* set_event_from_skb(skb)
 *
 * Populate the event args with the SKB 5-tuple when supported. Currently,
 * only supports IPv4 with TCP/UDP.
 */
static inline __attribute__((unused))
int set_event_from_skb(struct skb_type *event, struct sk_buff *skb) {

	unsigned char *skb_head = 0;
	u16 l3_off;

	probe_read(&skb_head, sizeof(skb_head), _(&skb->head));
	probe_read(&l3_off, sizeof(l3_off), _(&skb->network_header));

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	probe_read(&iphdr_byte0, 1, _(ip));

	u8 ip_ver = iphdr_byte0>>4;
	if (ip_ver == 4) { // IPv4
		u8 v4_prot;
		probe_read(&v4_prot, 1, _(&ip->protocol));

		event->proto = v4_prot;

		probe_read(&event->saddr, sizeof(event->saddr), _(&ip->saddr));
		probe_read(&event->daddr, sizeof(event->daddr), _(&ip->daddr));
		typeof(skb->transport_header) l4_off;
		probe_read(&l4_off, sizeof(l4_off), _(&skb->transport_header));
		if (v4_prot == 0x06) { // TCP
			struct tcphdr *tcp = (struct tcphdr *)(skb_head + l4_off);
			probe_read(&event->sport, sizeof(event->sport), _(&tcp->source));
			probe_read(&event->dport, sizeof(event->dport), _(&tcp->dest));
		} else if (v4_prot == 0x11) { // UDP
			struct udphdr *udp = (struct udphdr *)(skb_head + l4_off);
			probe_read(&event->sport, sizeof(event->sport), _(&udp->source));
			probe_read(&event->dport, sizeof(event->dport), _(&udp->dest));
		}

		return 0;
	} else if (ip_ver == 6) {
		return -1;
	}

	// This is not IP, so we don't know how to parse further.
	return -22;
}
#endif // __SKB_H__
