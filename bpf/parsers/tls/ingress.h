#ifndef ingress_h_INCLUDED
#define ingress_h_INCLUDED

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

#define ERROUT_LEN (5*24)

static inline __attribute__((always_inline))
void errout_pack(int *errout, int code, int a, int b, int c, int d) {
	errout[1] = code;
	errout[2] = a;
	errout[3] = b;
	errout[4] = c;
	errout[5] = d;
}

#define CERT_FRAG_MIN_LEN 6
#define FRAG_MAX_ITER 16

/* Find the end of a potentially fragmented handshake */
static inline __attribute__((always_inline))
int tls_find_handshake_end(struct bottle *bottle, int offset, int *type, int *subtype)
{
	struct tls_hdr *hdr;
	int remaining;
	u8 *data;

	/* Read the TLS record header + enough of the handshake header to figure
         * out the handshake message size. We assume that the handshake header
         * cannot be fragmented. */
	data = bottle_get_data(bottle, offset, sizeof(struct tls_hdr) + CERT_FRAG_MIN_LEN);
	if (!data)
		return TLS_PARSE_OUT_OF_DATA;

	hdr = (struct tls_hdr*)data;

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

static inline __attribute__((always_inline))
int bpf_parse_tls_cert(ctx_md *ctx,
                       struct bottle *bottle,
                       struct msg_tls *tls,
                       struct msg_tls_ipv4 *key,
                       u32 offset)
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
	event = bottle_get_data(bottle, offset - sizeof(struct msg_tls_cont_event), event_len);
	if (!event) {
		errcode = EBADHEADER;
		goto fail;
	}

	event->op = MSG_OP_TLS_CONT;
	event->tuple = *key;
	event->payload_size = end_offset - offset;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU,
	                  event, event_len);
	return 0;

fail:
	event = map_lookup_elem(&tls_heap, &zero);
	if (!event)
		return TLS_PARSE_ERROR;

	event->op = MSG_OP_TLS_CONT;
	event->tuple = *key;
	event->payload_size = 0;

	errout_pack((int*)event->payload, errcode, bottle->len, type, subtype, offset);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU,
	                  event, sizeof(*event) + ERROUT_LEN);
	return 0;
}

static inline __attribute__((always_inline))
void bpf_parse_ingress_skb(struct __sk_buff *skb, struct msg_tls_ipv4 *key, int offset)
{
	struct socketmap_value *execve;
	struct msg_tls *event;
	int zero = 0;

	event = map_lookup_elem(&tls_map, key);
	if (!event)
		return;

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
		post->common.op = MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = ktime_get_ns();

		execve  = lookup_socketmap(key);
		if (execve)
			post->execve = execve->key;

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;

		if (post->serverhello.flags & TLS_CERT) {
			event->bytes = next;
			next = bpf_parse_tls_cert(skb, bottle, event, key, next);
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
	}  else if (is_expected_tls_data(event)) {
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


#endif // ingress_h_INCLUDED

