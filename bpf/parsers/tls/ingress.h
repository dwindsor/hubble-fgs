// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef ingress_h_INCLUDED
#define ingress_h_INCLUDED

#include "../../networking/bpf_cookie.h"
#include "../../networking/l3/tcp/bpf_tcp_info.h"
/* HTTP used for KTLS handlers */
// #include "../http/http_parser.h"

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
		   __u64 socket_cookie, __u64 socket_version, u32 offset)
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

	/* To avoid a copy we write the event header on top of the now irrelevant data.
	       * Avoid integer underflow in second argument. */
	if (offset < sizeof(struct msg_tls_cont_event)) {
		errcode = EBADHEADER;
		goto fail;
	}
	event = bottle_get_data(bottle, offset - sizeof(struct msg_tls_cont_event), event_len);
	if (!event) {
		errcode = EBADHEADER;
		goto fail;
	}

	event->op = ISO_MSG_OP_TLS_CONT;
	event->socket_cookie = socket_cookie;
	event->socket_version = socket_version;
	event->payload_size = end_offset - offset;

	perf_event_output_metric(ctx, ISO_MSG_OP_TLS_CONT, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 event_len);
	return 0;

fail:
	event = map_lookup_elem(&tls_heap, &zero);
	if (!event)
		return TLS_PARSE_ERROR;

	event->op = ISO_MSG_OP_TLS_CONT;
	//event->tuple.saddr[0] = tuple->saddr[0];
	event->payload_size = 0;

	errout_pack((int *)event->payload, errcode, bottle->len, type, subtype,
		    offset);

	perf_event_output_metric(ctx, ISO_MSG_OP_TLS_CONT, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 sizeof(*event) + ERROUT_LEN);
	return 0;
}

static inline __attribute__((always_inline)) void
bpf_parse_ingress_skb(struct __sk_buff *skb, int offset)
{
	struct tcpsocketmap_value *socket;
	u64 cookie = (u64)skb->sk;
	struct msg_tls *event;
	int zero = 0;

	event = map_lookup_elem(&tg_tls_map, &cookie);
	if (!event)
		return;

	if (event->version == TLS_HTTP_VERSION) {
		/* Disabled ingress parsing waiting for upstream kernel bugfix to
		 * land in backports stable kernels.
		 */
		//	http_do_parser(skb, tuple);
		return;
	}

	socket = lookup_tcpsocketmap(&cookie);
	if (!socket)
		return;

	if (is_expected_tls_client_hello(event)) {
		struct msg_tls_event *post;
		struct bottle *bottle;
		int next;

		post = map_lookup_elem(&tls_heap, &zero);
		if (!post)
			return;

		bottle = bottle_fill(skb, &cookie, offset);
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

		post->common.op = ISO_MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = tg_get_ktime();

		post->execve = socket->key;
		post->socket_cookie = cookie;
		post->socket_version = socket->version;
		post->tuple = socket->tuple;

		perf_event_output_metric(skb, ISO_MSG_OP_TLS, &tcpmon_map, BPF_F_CURRENT_CPU, post,
					 sizeof(struct msg_tls_event));
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;

		if (post->serverhello.flags & TLS_CERT) {
			event->bytes = next;
			next = bpf_parse_tls_cert(skb, bottle, event, cookie, socket->version,
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
			bottle_drop(&cookie);
		}
	} else if (is_expected_tls_data(event)) {
		struct bottle *bottle;
		int err;

		bottle = bottle_fill(skb, &cookie, offset);
		if (!bottle) {
			tls_inc_bottle_fill_failed();
			return;
		}

		err = bpf_parse_tls_cert(skb, bottle, event, cookie, socket->version,
					 event->bytes);
		if (err == TLS_PARSE_OUT_OF_DATA) {
			tls_inc_ingress_out_of_data();
			event->type = TLS_TYPE_MORE_DATA;
		} else {
			if (err < 0)
				tls_inc_ingress_parse_error();
			else
				tls_inc_ingress_ok();
			tls_mark_complete(event);
			bottle_drop(&cookie);
		}
	}
}
#endif // ingress_h_INCLUDED
