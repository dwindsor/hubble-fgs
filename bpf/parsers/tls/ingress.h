#ifndef ingress_h_INCLUDED
#define ingress_h_INCLUDED

/* HTTP used for KTLS handlers */
#include "../http/http_parser.h"

/*
 * Certificate parsing
 *
 * The BPF side for certificate parsing finds the end of the last certificate
 * fragment message and sends all fragments to the agent for reassembly.
 */

/* TLS Certificate Error Codes */
#define EBADHEADER 0x0001

/* TLS Certificate Hdr offset */
#define TLS_HEADER_BYTES 9

#define ERROUT_LEN (5 * 24)

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

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(max_entries, 1);
} cilium_snat_v4_external SEC(".maps");

static inline __attribute__((always_inline)) void
skb_tls_key_ct_xchg(struct msg_tls_ip *key)
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
	ct.daddr = key->daddr[0];
	ct.saddr = key->saddr[0];
	ct.dport = bpf_htons(key->dport);
	ct.sport = bpf_htons(key->sport);
	ct.nexthdr = IPPROTO_TCP;
	ct.flags = 1;

	nat = map_lookup_elem(&cilium_snat_v4_external, &ct);
	if (nat) {
		key->daddr[0] = nat->to_daddr;
		key->dport = bpf_ntohs(nat->to_dport);
	}

	/* Swap key to match egress side */
	addr = key->saddr[0];
	key->saddr[0] = key->daddr[0];
	key->daddr[0] = addr;

	port = key->sport;
	key->sport = key->dport;
	key->dport = port;
}

static inline __attribute__((always_inline)) void
errout_pack(int *errout, int code, int a, int b, int c, int d)
{
	errout[1] = code;
	errout[2] = a;
	errout[3] = b;
	errout[4] = c;
	errout[5] = d;
}

#define CERT_FRAG_MIN_LEN 6
#define FRAG_MAX_ITER	  8

/* Find the end of a potentially fragmented handshake */
static inline __attribute__((always_inline)) int
tls_find_handshake_end(struct bottle *bottle, int offset, int *type,
		       int *subtype)
{
	struct tls_hdr *hdr;
	int remaining;
	u8 *data;

	/* Read the TLS record header + enough of the handshake header to figure
         * out the handshake message size. We assume that the handshake header
         * cannot be fragmented. */
	data = bottle_get_data(bottle, offset,
			       sizeof(struct tls_hdr) + CERT_FRAG_MIN_LEN);
	if (!data)
		return TLS_PARSE_OUT_OF_DATA;

	hdr = (struct tls_hdr *)data;

	*type = hdr->type;
	if (hdr->type != TLS_TYPE_HANDSHAKE)
		return TLS_PARSE_ERROR;

	data += sizeof(struct tls_hdr);

	/* Parse the subtype and length out of the handshake header
         * [ type (8b) | handshake length (24b) | ... ]
         */
	*subtype = *data++;
	remaining = *data << 16 | *(data + 1) << 8 | *(data + 2);
	remaining += 4;

	/* Iterate over the fragments until we find the end of the last fragment. */
#pragma unroll
	for (int i = 0; i < FRAG_MAX_ITER; i++) {
		u32 frag_len = bpf_ntohs(hdr->length) & 0xfff;
		offset += sizeof(struct tls_hdr);

		data = bottle_get_data(bottle, offset, frag_len);
		if (!data)
			return TLS_PARSE_OUT_OF_DATA;

		offset += frag_len;
		remaining -= frag_len;
		if (remaining <= 0) {
			break;
		}

		hdr = bottle_get_data(bottle, offset, sizeof(struct tls_hdr));
		if (!hdr)
			return TLS_PARSE_OUT_OF_DATA;
	}

	/* Too many fragments. Give up. */
	if (remaining > 0)
		return TLS_PARSE_ERROR;

	return offset;
}

static inline __attribute__((always_inline)) int
bpf_parse_tls_cert(ctx_md *ctx, struct bottle *bottle, struct msg_tls *tls,
		   struct msg_tls_ip *key, u32 offset)
{
	struct msg_tls_cont_event *event;
	int type = 0, subtype = 0;
	int end_offset;
	int event_len;
	int zero = 0;
	int errcode = 0;

	/* First find where the handshake protocol ends. This may span
         * multiple fragments and packets. */
	end_offset = tls_find_handshake_end(bottle, offset, &type, &subtype);
	if (end_offset == TLS_PARSE_OUT_OF_DATA)
		return TLS_PARSE_OUT_OF_DATA;

	if (end_offset <= 0 || subtype != TLS_HANDSHAKE_TYPE_CERTIFICATE) {
		errcode = EBADHEADER;
		goto fail;
	}

	/* Now that all the data is accounted for, send the fragments to the agent. */
	event_len = (sizeof(struct msg_tls_cont_event) + end_offset - offset);
	BOTTLE_MASK(event_len);

	/* To avoid a copy we write the event header on top of the now irrelevant data. */
	event = bottle_get_data(
		bottle, offset - sizeof(struct msg_tls_cont_event), event_len);
	if (!event) {
		errcode = EBADHEADER;
		goto fail;
	}

	event->op = ISO_MSG_OP_TLS_CONT;
	event->tuple = *key;
	event->payload_size = end_offset - offset;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event,
			  event_len);
	return 0;

fail:
	event = map_lookup_elem(&tls_heap, &zero);
	if (!event)
		return TLS_PARSE_ERROR;

	event->op = ISO_MSG_OP_TLS_CONT;
	event->tuple = *key;
	event->payload_size = 0;

	errout_pack((int *)event->payload, errcode, bottle->len, type, subtype,
		    offset);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event,
			  sizeof(*event) + ERROUT_LEN);
	return 0;
}

static inline __attribute__((always_inline)) void
bpf_parse_ingress_skb(struct __sk_buff *skb, struct msg_tls_ip *key, int offset)
{
	struct socketmap_value *execve;
	struct msg_tls *event;
	int zero = 0;
	u64 *cookie;

	event = map_lookup_elem(&tls_map, key);
	if (!event)
		return;

	if (event->version == TLS_HTTP_VERSION) {
		/* Disabled ingress parsing waiting for upstream kernel bugfix to
		 * land in backports stable kernels.
		 */
		//	http_do_parser(skb, key);
		return;
	}

	if (is_expected_tls_client_hello(event)) {
		struct msg_tls_event *post;
		struct bottle *bottle;
		int next;

		post = map_lookup_elem(&tls_heap, &zero);
		if (!post)
			return;

		bottle = bottle_fill(skb, key, offset);
		if (!bottle) {
			tls_inc_bottle_fill_failed();
			tls_mark_complete(event);
			return;
		}

		post->clienthello = *event;
		memset(&post->serverhello, 0, sizeof(post->serverhello));

		next = bpf_parse_tls(bottle, &post->serverhello);
		if (next < 0)
			goto out;

		if (!is_expected_tls_server_hello(&post->serverhello))
			goto out;

		/* If this there is a next pointer and it is TLSv1.2 lets assume
		 * its the cert and push it to user space.
		 */
		if (!(post->serverhello.flags & TLS_VERSION))
			post->serverhello.flags |= TLS_CERT;

		post->tuple = *key;
		post->common.op = ISO_MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = ktime_get_ns();

		cookie = map_lookup_elem(&tls_cookie_heap, &zero);
		if (!cookie)
			return;
		write_cookie_from_sk(cookie, (struct sock *)skb->sk, true);
		if (!*cookie)
			return;
		execve = lookup_socketmap(cookie);
		if (execve)
			post->execve = execve->key;

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;

		if (post->serverhello.flags & TLS_CERT) {
			event->bytes = next;
			next = bpf_parse_tls_cert(skb, bottle, event, key,
						  next);
			if (next == TLS_PARSE_OUT_OF_DATA) {
				event->type = TLS_TYPE_MORE_DATA;
			}
		}

	out:
		if (next == TLS_PARSE_OUT_OF_DATA) {
			tls_inc_ingress_out_of_data();
		} else {
			if (next < 0)
				tls_inc_ingress_parse_error();
			else
				tls_inc_ingress_ok();

			tls_mark_complete(event);
			bottle_drop(key);
		}
	} else if (is_expected_tls_data(event)) {
		struct bottle *bottle;
		int err;

		bottle = bottle_fill(skb, key, offset);
		if (!bottle) {
			tls_inc_bottle_fill_failed();
			return;
		}

		err = bpf_parse_tls_cert(skb, bottle, event, key, event->bytes);
		if (err == TLS_PARSE_OUT_OF_DATA) {
			tls_inc_ingress_out_of_data();
			event->type = TLS_TYPE_MORE_DATA;
		} else {
			if (err < 0)
				tls_inc_ingress_parse_error();
			else
				tls_inc_ingress_ok();
			tls_mark_complete(event);
			bottle_drop(key);
		}
	}
}

static inline __attribute__((always_inline)) void
event_tc_ingress_tcp(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		     struct tcphdr *tcp, u64 *cookie, int payload_off)
{
	struct msg_tls_ip key = { 0 };

	/* IPv6 not currently supported. Coming in later commit.
	 */
	if (ipv6)
		return;

	key.daddr[0] = ip->daddr;
	key.saddr[0] = ip->saddr;
	key.ipv6 = 0;
	key.dport = tcp->dest;
	key.sport = tcp->source;

	skb_tls_key_ct_xchg(&key);
	/* Hooks read sport in network order, but rest of stack
	 * expects host order for sport so we do conversion here after
	 * xchg to get correct sport/dports. We do not need to do
	 * anything with dport because the original pre-xchged sport
	 * was in network byte order being read directly from packet
	 * data.
	 */
	key.sport = bpf_ntohs(key.sport);
	bpf_parse_ingress_skb(skb, &key, payload_off);

	return;
}

#endif // ingress_h_INCLUDED
