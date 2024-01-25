#ifndef __BPF_DNS_H_
#define __BPF_DNS_H_

#include "../bpf_udp_event.h"

static inline __attribute__((always_inline)) int
dns_port_match(u16 *ports, u16 port1, u16 port2)
{
	if (ports[0] == port1 || ports[0] == port2 || ports[1] == port1 ||
	    ports[1] == port2 || ports[2] == port1 || ports[2] == port2 ||
	    ports[3] == port1 || ports[3] == port2) {
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline)) int
udp_dns(struct __sk_buff *skb,
	void *skb_head,
	struct udp_info_value *value,
	struct iphdr *ip,
	bool ipv6,
	u64 *cookie,
	int payload_off,
	int payload_sz)
{
	struct udp_sensor_config *config = get_udp_config();
	bool store = true;
	int isdns;

	if (!config)
		return 0;

	if (config->dnsPorts[0] == 0)
		return 0;

	isdns = dns_port_match(config->dnsPorts, value->sport, value->dport);
	if (!isdns)
		return 0;

#ifndef MISSING_PERFEVENT
	if (value->pid) {
		/* We subtract 1 from payload_sz because we need to +1 it
		 * later to sat verifier constraint that skb_load_bytes
		 * must be nonzero.
		 */
		emit_udp_payload_event(skb, ip, cookie, ipv6,
				       value, payload_off,
				       payload_sz - 1);
		store = false;
	}
#endif // MISSING_PERFEVENT

	/* Either the PID is empty because we couldn't look up
	 * the process in the cookie->process map or we got
	 * here from a <4.20 kernel where cgroups didn't support
	 * perf events yet. Either way store the event for the
	 * API-level function (either udp_sendret or udp_recv) to
	 * add process information and then transmit it.
	 */
	if (store && payload_off != -1) {
		// Check payload offset is valid.
		store_udp_payload_event(
			skb, ip, cookie, ipv6, skb_head,
			value, payload_off,
			payload_sz - 1);
	}
	return 1;
}
#endif
