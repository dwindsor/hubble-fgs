#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_events.h"
#include "tls_map.h"
#include "tls_parser.h"
#include "ingress.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct nat_entry {
	__u64 created;
	__u64 host_local; /* Only single bit used. */
	__u64 pad1; /* Future use. */
	__u64 pad2; /* Future use. */
};

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic. */
	__be32 daddr;
	__be32 saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic. */
	__be16 dport;
	__be16 sport;
	__u8 nexthdr;
	__u8 flags;
} __attribute__((packed));

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct bpf_map_def __attribute__((section("maps"), used))
cilium_snat_v4_external = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct ipv4_ct_tuple),
	.value_size = sizeof(struct ipv4_nat_entry),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) void
skb_tls_key_ct_xchg(struct msg_tls_ipv4 *key)
{
	struct ipv4_ct_tuple ct = { 0 };
	struct ipv4_nat_entry *nat;
	__u32 addr;
	__u16 port;

	/* Egress hook runs in-front of Cilium SNAT, so it used same IP addr pairs
	 * as seen by socket. But, ingress hook is also running in front Cilium
	 * SNAT so the TCP key is before NAT and needs to be translated using
	 * the BPF map.
	 */
	ct.daddr = key->daddr;
	ct.saddr = key->saddr;
	ct.dport = bpf_htons(key->dport);
	ct.sport = bpf_htons(key->sport);
	ct.nexthdr = IPPROTO_TCP;
	ct.flags = 1;

	nat = map_lookup_elem(&cilium_snat_v4_external, &ct);
	if (nat) {
		key->daddr = nat->to_daddr;
		key->dport = bpf_ntohs(nat->to_dport);
	}

	/* Swap key to match egress side */
	addr = key->saddr;
	key->saddr = key->daddr;
	key->daddr = addr;

	port = key->sport;
	key->sport = key->dport;
	key->dport = port;
}

__attribute__((section(("classifier/ingress_tcp")), used)) int
event_tc_ingress_tcp(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = { 0 };
	struct tcphdr *tcp;
	int off = 0;

	tcp = skb_tls_key(skb, &off, &key);
	if (!tcp)
		return TC_ACT_UNSPEC;

	if (!skb_tcp_payload(skb, tcp, &off)) {
		return TC_ACT_UNSPEC;
	}

	skb_tls_key_ct_xchg(&key);
	/* TC hooks read sport in network order, but rest of stack
	 * expects host order for sport so we do conversion here after
	 * xchg to get correct sport/dports. We do not need to do
	 * anything with dport because the original pre-xchged sport
	 * was in network byte order being read directly from packet
	 * data.
	 */
	key.sport = bpf_ntohs(key.sport);
	bpf_parse_ingress_skb(skb, &key, off);

	return TC_ACT_UNSPEC;
}
