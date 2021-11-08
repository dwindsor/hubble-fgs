#include "api.h"
#include "../parser.h"
#include "tls_map.h"
#include "../msg_bottle.h"

#ifdef SK_MSG
typedef struct sk_msg_md ctx_md;
#else
typedef struct __sk_buff ctx_md;
#endif

struct bpf_map_def __attribute__((section("maps"), used)) tls_heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_tls_event),
	.max_entries = 1,
};

struct tls_hdr {
	__u8  type;
	__u16 version;
	__u16 length;
} __attribute__((packed));

struct tls_random {
	__u32 gmt_unix_time;
	__u8  random[28];
} __attribute__((packed));

struct tls_alert {
	__u8 level;
	__u8 description;
} __attribute__((packed));

struct tls_handshake_hdr {
	__u32 type:8;
	__u32 length:24;
	__u16 version;
} __attribute__((packed));

struct tls_handshake_client_hello {
	__u32 type:8;
	__u32 length:24;
	__u16 version;
	struct tls_random random;
	__u8  session_id_length;
} __attribute__((packed));

struct tls_handshake_server_hello {
	__u32 type:8;
	__u32 length:24;
	__u16 version;
	struct tls_random random;
	__u8  session_id_length;
} __attribute__((packed));

struct tls_extension {
	__u16 type;
	__u16 length;
} __attribute__((packed));

#ifndef bpf_ntohs
#define bpf_ntohs(x)		__builtin_bswap16(x)
#endif

#ifndef bpf_htons
#define bpf_htons(x)		__builtin_bswap16(x)
#endif

#ifndef bpf_ntohl
#define bpf_ntohl(x)		__builtin_bswap32(x)
#endif

#ifndef bpf_htonl
#define bpf_htonl(x)		__builtin_bswap32(x)
#endif

#define TLS_TYPE_MORE_DATA  1
#define TLS_TYPE_HANDSHAKE_COMPLETE 2
#define TLS_TYPE_ALERT 21
#define TLS_TYPE_HANDSHAKE 22

#define TLS_HANDSHAKE_TYPE_CERTIFICATE 11

#define TLS_VERSION_13 0x0403
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_11 0x0203
#define TLS_VERSION_10 0x0103

enum tls_parser_error {
	TLS_PARSE_BAD_DATA = -1,
	TLS_PARSE_OUT_OF_DATA = -2,
};

enum tls_handshake_type {
	hello_request = 0,
	client_hello = 1,
	server_hello = 2,
	certificate = 11,
	server_key_exchange = 12,
	certificate_request = 13,
	server_hello_done = 14,
	certificate_verify = 15,
	client_key_exchange = 16,
	finished = 20,
};

static inline __attribute__((always_inline))
int bpf_parse_tls_hello_request(struct sk_msg_md *msg)
{
	return 0;
}

#define MAX_EXT_LENGTH 255
#define EXTENSION { \
	extension = bpf_parse_extension(extension, data_end, tls); \
	if (!extension)						   \
		goto extension_macro_out;			   \
}

#define TWO_EXTENSIONS { \
	EXTENSION	 \
	EXTENSION	 \
}
#define TEN_EXTENSIONS { \
	TWO_EXTENSIONS   \
	TWO_EXTENSIONS   \
	TWO_EXTENSIONS   \
	TWO_EXTENSIONS   \
	TWO_EXTENSIONS   \
}

#define TWENTY_EXTENSIONS { \
	TEN_EXTENSIONS      \
	TEN_EXTENSIONS      \
}

#define EXT_SERVER_NAME 0
#define EXT_SUPPORTED_VERSION 43

static inline __attribute__((always_inline))
struct tls_extension *bpf_parse_extension(struct tls_extension *extension, void *data_end, struct msg_tls *tls)
{
	__u16 extlength, exttype;
	void *dst = 0;

	if ((void *)extension + 4 > data_end)
		return 0;

	extlength = bpf_htons(extension->length);
	exttype = bpf_htons(extension->type);

	switch (exttype) {
	case EXT_SERVER_NAME:
		dst = tls->sni;
		break;
	case EXT_SUPPORTED_VERSION:
		dst = tls->supported_versions;
		tls->flags |= TLS_VERSION;
		break;
	}

	if (dst) {
		stack_pkt_copy(dst, data_end, (void *)extension + 4, extlength);
		if (extlength > EXT_SERVER_NAME_LENGTH)
			tls->flags |= TLS_COPY_ERROR;
	}

	/* Assuming SNI is first extension, per specification */
	if (tls->flags & TLS_VERSION)
		return 0;

	/* Force compiler to use same register for min/max bound generators */
	asm volatile (
		"%[extlength] &= 0x7fff;\n"
		"if %[extlength] >= 255 goto +3;\n"
		"%[extlength] += 4;\n"
		"%[extension] += %[extlength];\n"
		"goto + 1;\n"
		"%[extension] = 0;\n"
		: [extlength] "+r"(extlength),
		  [extension] "+r"(extension)
		:  :);
	return extension;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_client_hello(struct msg_bottle *bottle, struct msg_tls *tls, bool client)
{
	__u16 *cipher_length, adv_cipher, extlength;
	int offset = sizeof(struct tls_hdr);
	struct tls_handshake_client_hello *client_hello;
	__u8 *session, *compression, adv_compression, adv_session;
	struct tls_extension *extension;
	void *data_end;

	client_hello = msg_bottle_get_data(bottle, offset, sizeof(struct tls_handshake_client_hello));
	if (!client_hello) {
		tls->flags |= TLS_HELLO_MSG_MISS;
		return TLS_PARSE_OUT_OF_DATA;
	}
	offset += sizeof(struct tls_handshake_client_hello);

	compiler_barrier();
	adv_session = client_hello->session_id_length;
	adv_session &= 0x7fff;

	session = msg_bottle_get_data(bottle, offset, adv_session);
	if (!session)
		return TLS_PARSE_OUT_OF_DATA;
	offset += adv_session;

#ifdef SK_MSG
	small_pkt_copy(tls->session, bottle->data_end, session, 64);
#else
	small_pkt_copy(tls->session, (void*)client_hello + offset, session, 64);
#endif

	cipher_length = msg_bottle_get_data(bottle, offset, 2);
	if (!cipher_length)
		return TLS_PARSE_OUT_OF_DATA;
	offset += 2;

	if (client) {
		adv_cipher = *cipher_length;
		adv_cipher = bpf_htons(adv_cipher);
	} else {
		tls->cipher = *(__u16*)cipher_length;
		adv_cipher = 0;
	}

	if (adv_cipher > 255) {
		tls->flags |= TLS_CIPHER_TOO_LARGE;
		return TLS_PARSE_BAD_DATA;
	}
	asm volatile (
		"if %[adv_cipher] s> 0 goto +1;\n"
		"%[adv_cipher] = 0;\n"
		: [adv_cipher] "+r" (adv_cipher)::);

	offset += adv_cipher;

	compression = msg_bottle_get_data(bottle, offset, 1);
	if (!compression) {
		tls->flags |= TLS_COMPRESSION_ERROR;
		return TLS_PARSE_OUT_OF_DATA;
	}

	if (client)
		adv_compression = *compression;
	else
		adv_compression = 0;

	compiler_barrier();
	adv_compression &= 0x7f;
	if (adv_compression > 255) {
		tls->flags |= TLS_COMPRESSION_TOO_LARGE;
		return TLS_PARSE_BAD_DATA;
	}
	offset += adv_compression + 1;

	extension = msg_bottle_get_data(bottle, offset, 2);
	if (!extension) {
		tls->flags |= TLS_EXT_ERROR;
		return TLS_PARSE_OUT_OF_DATA;
	}
	offset += 2;

	extlength = *(u16 *)extension;
	extlength = bpf_htons(extlength);
	asm volatile (
		"if %[extlength] > 2 goto +1;\n"
		"%[extlength] = 0;\n"
		: [extlength] "+r"(extlength)::);
	extension = msg_bottle_get_data(bottle, offset, extlength);
	if (!extension) {
		tls->flags |= TLS_EXT_ERROR;
		return TLS_PARSE_OUT_OF_DATA;
	}
#ifdef SK_MSG
	data_end = bottle->data_end;
#else
	data_end = (void*)extension + extlength;
#endif
	TWENTY_EXTENSIONS
	tls->flags |= TLS_MAX_TLVS;
extension_macro_out:
	return 0;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_certificate(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_server_key_exchange(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_certificate_request(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_server_hello_done(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_certificate_verify(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_client_key_exchange(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_finished(struct sk_msg_md *msg)
{
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_skb(struct __sk_buff *skb, struct msg_tls *tls)
{
	void *data_end = (void *)(long) skb->data_end;
	void *data = (void *)(long) skb->data;
	struct tls_hdr *copy;
	__u8 doff, tcp_off;
	__u8 *ihl, *data_off, *payload;

	ihl = data;
	if (ihl + 1 > data_end)
		return 0;

	tcp_off = *ihl;
	tcp_off &= 0x0f;
	tcp_off *= 4;
	data_off = data + tcp_off + 12;
	if (data_off + 1 > data_end)
		return 0;
	doff = *data_off;
	doff = ((doff >> 4) * 4);
	payload = data + tcp_off + doff;
	if (payload + sizeof(struct tls_hdr) > data_end)
		return 0;
	copy = (struct tls_hdr*) payload;
	tls->type    = copy->type;
	tls->length  = copy->length;
	tls->version = copy->version;
	return 0;
}

static inline __attribute__((always_inline))
bool is_tls_handshake(struct msg_tls *tls)
{
	return tls->type == TLS_TYPE_HANDSHAKE;
}

static inline __attribute__((always_inline))
bool is_tls_client_hello_handshake(struct msg_tls *tls)
{
	return is_tls_handshake(tls) && tls->subtype == client_hello;
}

static inline __attribute__((always_inline))
bool is_tls_server_hello_handshake(struct msg_tls *tls)
{
	return is_tls_handshake(tls) && tls->subtype == server_hello;
}

static inline __attribute__((always_inline))
bool is_tls_version(struct msg_tls *tls)
{
	switch (tls->version) {
	case TLS_VERSION_12:
	case TLS_VERSION_11:
	case TLS_VERSION_10:
		return true;
	default:
		return false;
	}
}

static inline __attribute__((always_inline))
bool is_tls_more_data(struct msg_tls*tls)
{
	return tls->type == TLS_TYPE_MORE_DATA;
}

static inline __attribute__((always_inline))
bool is_expected_tls_data(struct msg_tls *tls)
{
	return is_tls_more_data(tls);
}

static inline __attribute__((always_inline))
bool is_expected_tls_client_hello(struct msg_tls *tls)
{
	return is_tls_client_hello_handshake(tls) && is_tls_version(tls);
}

static inline __attribute__((always_inline))
bool is_expected_tls_server_hello(struct msg_tls *tls)
{
	return is_tls_server_hello_handshake(tls) && is_tls_version(tls);
}

static inline __attribute__((always_inline))
int bpf_parse_tls(struct msg_bottle *bottle,
		  struct msg_tls *tls)
{
	struct tls_hdr *hdr;
	int next = 0, err;
	void *payload;

	payload = msg_bottle_get_data(bottle, 0, sizeof(struct tls_hdr));
	if (!payload)
		return TLS_PARSE_OUT_OF_DATA;

	hdr = (struct tls_hdr *)payload;

	tls->type    = hdr->type;
	tls->length  = hdr->length;
	tls->version = hdr->version;

	if (hdr->type == TLS_TYPE_HANDSHAKE) {
		struct tls_handshake_hdr *handshake;
		bool client = false;

		payload = msg_bottle_get_data(bottle, 0, sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr));
		if (!payload) {
			tls->flags |= TLS_HANDSHAKE_MSG_MISS;
			return TLS_PARSE_OUT_OF_DATA;
		}
		handshake = (struct tls_handshake_hdr *)(payload + sizeof(struct tls_hdr));
		tls->subtype = handshake->type;
		tls->version = handshake->version;
		switch (handshake->type) {
		case client_hello:
			client = true;
		case server_hello:
			err = bpf_parse_tls_client_hello(bottle, tls, client);
			if (err)
				return err;

			next = sizeof(struct tls_hdr) + bpf_ntohs(tls->length);
			break;
		default:
			break;
		}
	} else if (hdr->type == TLS_TYPE_ALERT) {
		struct tls_alert *tls_alert;

		payload = msg_bottle_get_data(bottle, 0,
			sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr));

		if (!payload)
			return TLS_PARSE_OUT_OF_DATA;
		tls_alert = (struct tls_alert *)(payload + sizeof(struct tls_hdr));
		tls->alert_level = tls_alert->level;
		tls->alert_description = tls_alert->description;
		/* Advance pointer to end of alert */
		next = sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr);
	} else {
		return TLS_PARSE_BAD_DATA;
	}
	return next;
}

#define ETH_P_IP 0x800
#define TLS_REMOTE_PORT 443

#ifdef SK_MSG
static inline __attribute__((always_inline))
void skb_tls_key(struct sk_msg_md *skmsg, struct msg_tls_ipv4 *key) {
	key->daddr = skmsg->remote_ip4;
	key->saddr = skmsg->local_ip4;
	key->dport = TLS_REMOTE_PORT;
	key->sport = skmsg->local_port;
}
#elif defined(SK_SKB)
static inline __attribute__((always_inline))
void sk_skb_tls_key(struct __sk_buff *skb, struct msg_tls_ipv4 *key)
{
	key->daddr = skb->remote_ip4;
	key->saddr = skb->local_ip4;
	key->dport = TLS_REMOTE_PORT;
	key->sport = skb->local_port;
}
#else
static inline __attribute__((always_inline))
void *skb_tls_key(struct __sk_buff *skb, int *off, struct msg_tls_ipv4 *key) {
	void *data, *data_end;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	__u8 tcp_off;
	__u16 proto;

	data = (void *)(long) skb->data;
	data_end = (void *)(long) skb->data_end;
	eth = data;
	/* TBD soon data, data_end, payload will be streamified and and
	 * the extra data_end reset will be dropped.
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		eth = get_data(skb, 0, sizeof(struct ethhdr) + sizeof(struct iphdr));
		if (!eth)
			return 0;
		data_end = (void *)(long)skb->data_end;
	}

	proto = eth->h_proto;
	if (proto != bpf_htons(ETH_P_IP))
		return 0;

	iphdr = (void *)eth + sizeof(struct ethhdr);
	key->daddr = iphdr->daddr;
	key->saddr = iphdr->saddr;

	if (iphdr->protocol != IPPROTO_TCP)
		return 0;

	tcp_off = iphdr->ihl;
	tcp_off &= 0x0f;
	tcp_off *= 4;
	tcphdr = (void *)iphdr + tcp_off;
	if (tcphdr + sizeof(struct tcphdr) > data_end) {
		tcphdr = get_data(skb,
				sizeof(struct ethhdr) + tcp_off, sizeof(struct tcphdr));
		if (!tcphdr)
			return 0;
		data_end = (void *)(long)skb->data_end;
	}

	key->dport = bpf_htons(tcphdr->dest);
	key->sport = bpf_htons(tcphdr->source);
	*off = tcp_off + sizeof(struct ethhdr);
	return (void *)tcphdr;
}

static inline __attribute__((always_inline))
void *skb_tcp_payload(struct __sk_buff *skb, struct tcphdr *tcphdr, int *offset)
{
	void *data_end;
	__u8 doff;

	/* Under code refactor clang was putting a <<32,>>32 here to
	 * apparently zero up 32bits of data_end. But, this broke
	 * verifier on 4.19 kernels. Lets tell clang how to do this
	 * with asm.
	 */
	asm volatile(
		"%[data_end] = *(u32*)%[skb_end];\n"
		: [data_end] "+r"(data_end)
		:  [skb_end] "m"(skb->data_end)
		:);

	/* offset of doff + 4B read */
	if ((void *)tcphdr + sizeof(struct tcphdr) > data_end) {
		tcphdr = get_data(skb, *offset, 16);
		if (!tcphdr)
			return 0;
	}
	doff = tcphdr->doff;
	doff *= 4;
	/* Subtraction on pointers is only supported on newer kernels so we
	 * have to track offset instead of just take difference.
	 */
	*offset = *offset + doff;
	return (void*)tcphdr + doff;
}
#endif

/*
 * Certificate parsing
 *
 * The BPF side for certificate parsing finds the end of the last certificate
 * fragment message and sends all fragments to the agent for reassembly.
 */
#ifndef SK_MSG

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
int tls_find_handshake_end(struct msg_bottle *bottle, int offset, int *type, int *subtype)
{
	struct tls_hdr *hdr;
	int remaining;
	u8 *data;

	/* Read the TLS record header + enough of the handshake header to figure
         * out the handshake message size. We assume that the handshake header
         * cannot be fragmented. */
	data = msg_bottle_get_data(bottle, offset, sizeof(struct tls_hdr) + CERT_FRAG_MIN_LEN);
	if (!data)
		return TLS_PARSE_OUT_OF_DATA;

	hdr = (struct tls_hdr*)data;

	*type = hdr->type;
	if (hdr->type != TLS_TYPE_HANDSHAKE)
		return TLS_PARSE_BAD_DATA;

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

		data = msg_bottle_get_data(bottle, offset, frag_len);
		if (!data)
			return TLS_PARSE_OUT_OF_DATA;

		offset += frag_len;
		remaining -= frag_len;
		if (remaining <= 0) {
			break;
		}

		hdr = msg_bottle_get_data(bottle, offset, sizeof(struct tls_hdr));
		if (!hdr)
			return TLS_PARSE_OUT_OF_DATA;
	}

	/* Too many fragments. Give up. */
	if (remaining > 0)
		return TLS_PARSE_BAD_DATA;

	return offset;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_cert(ctx_md *ctx,
                       struct msg_bottle *bottle,
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
	event = msg_bottle_get_data(bottle, offset - sizeof(struct msg_tls_cont_event), event_len);
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
		return TLS_PARSE_BAD_DATA;

	event->op = MSG_OP_TLS_CONT;
	event->tuple = *key;
	event->payload_size = 0;

	errout_pack((int*)event->payload, errcode, bottle->len, type, subtype, offset);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU,
	                  event, sizeof(*event) + ERROUT_LEN);
	return 0;
}

/* Mark a TLS entry as completed to stop further parsing. */
static inline __attribute__((always_inline))
void tls_mark_complete(struct msg_tls *tls)
{
	tls->type = 0;
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
		struct skb_bottle *bottle;
		int next;

		post = map_lookup_elem(&tls_heap, &zero);
		if (!post)
			return;

		bottle = skb_bottle_fill(skb, key, offset);
		if (!bottle) {
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

		/* Set dport to network byte order as that's what socketmap
                 * expects. */
		key->dport = bpf_htons(key->dport);
		execve  = lookup_socketmap(key);
		if (execve)
			post->execve = execve->key;
		key->dport = bpf_ntohs(key->dport);

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;

		if (post->serverhello.flags & TLS_CERT) {
			event->bytes = next;
			next = bpf_parse_tls_cert(skb, bottle, event, key, next);
			if (next < 0) {
				event->type = TLS_TYPE_MORE_DATA;
			}
		}

out:
		if (next != TLS_PARSE_OUT_OF_DATA) {
			/* Parsing has failed. Drop the data. */
			tls_mark_complete(event);
			map_delete_elem(&skb_bottles, key);
		}

	}  else if (is_expected_tls_data(event)) {
		struct skb_bottle *bottle;
		int err;

		bottle = skb_bottle_fill(skb, key, offset);
		if (!bottle)
			// TODO need to post an error event?
			return;

		err = bpf_parse_tls_cert(skb, bottle, event, key, event->bytes);
		if (err == TLS_PARSE_OUT_OF_DATA) {
			event->type = TLS_TYPE_MORE_DATA;
		} else {
			tls_mark_complete(event);
			map_delete_elem(&skb_bottles, key);
		}
	}
}

#endif
