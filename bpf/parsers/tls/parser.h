#include "api.h"
#include "../parser.h"

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

struct tls_handshake_certificate {
	__u32 type:8;
	__u32 version:16;
	__u32 length:16;
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
#define TLS_TYPE_ALERT 21
#define TLS_TYPE_HANDSHAKE 22

#define TLS_VERSION_13 0x0403
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_11 0x0203
#define TLS_VERSION_10 0x0103

#define EIO 5

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
		if (extlength > 32)
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
#ifndef SK_MSG
int bpf_parse_tls_client_hello(struct __sk_buff *ctx, __u64 payload_off, struct msg_tls *tls, bool client)
{
#else
int bpf_parse_tls_client_hello(struct sk_msg_md *ctx, __u64 dummy, struct msg_tls *tls, bool client)
{
	/* Its a bit of a trick to get compiler to generate this
	 * without lsh/srsh pattern which breaks verifier.
	 */
	int payload_off = 0;
#endif
	__u16 *cipher_length, adv_cipher, extlength;
	int offset = payload_off;
	struct tls_handshake_client_hello *client_hello;
	__u8 *session, *compression, adv_compression, adv_session;
	struct tls_extension *extension;
	volatile __u32 maxlength;
	void *payload, *data, *data_end;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	asm volatile(
		"if %[payload_off] > 0 goto +1;\n"
		"%[payload_off] = 0;\n"
		: [payload_off] "+r"(payload_off)::);
	asm volatile(
		"if %[payload_off] < 4096 goto +1;\n"
		"%[payload_off] = 0;\n"
		: [payload_off] "+r"(payload_off)::);

#if defined(SK_MSG) || defined(SK_SKB)
	payload = data;
#else
	payload = data + payload_off;
#endif

	client_hello = payload + sizeof(struct tls_hdr);
	if ((void*)client_hello + sizeof(struct tls_handshake_client_hello) > data_end) {
		client_hello = get_data(ctx,
					payload_off + sizeof(struct tls_hdr),
					sizeof(struct tls_handshake_client_hello));
		if (!client_hello) {
			tls->flags |= TLS_HELLO_MSG_MISS;
			return SK_PASS;
		}
		data_end = (void *)(long)ctx->data_end;
	}

	/* If you (a) have lots of extensions and (b) don't put required extensions in
	 * the front of the list go away we may drop your packets for fun.
	 */
	maxlength = *(u32*)client_hello;
	maxlength &= 0xFFFFFF00;
	maxlength = bpf_ntohl(maxlength);
	maxlength &= 0x7fffff;
	if (maxlength > 1000)
		maxlength = 1000;

	compiler_barrier();
	adv_session = client_hello->session_id_length;
	adv_session &= 0x7fff;

	offset = payload_off + adv_session +
		sizeof(struct tls_handshake_client_hello) +
		sizeof(struct tls_hdr);
	cipher_length = get_data(ctx, offset, 2);
	if (!cipher_length) {
		tls->flags |= TLS_CIPHER_ERROR;
		return -EIO;
	}
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
#if defined(SK_MSG) || defined(SK_SKB)
	payload = data;
#else
	payload = data + payload_off;
#endif
	client_hello = payload + sizeof(struct tls_hdr);

	session = (void*)client_hello + 6;
	small_pkt_copy(tls->session, data_end, session, 64);
	if (client) {
		adv_cipher = *cipher_length;
		adv_cipher = bpf_htons(adv_cipher);
	} else {
		tls->cipher = *(__u16*)cipher_length;
		adv_cipher = 0;
	}

	if (adv_cipher > 255) {
		tls->flags |= TLS_CIPHER_TOO_LARGE;
		return -EIO;
	}
	asm volatile (
		"if %[adv_cipher] s> 0 goto +1;\n"
		"%[adv_cipher] = 0;\n"
		: [adv_cipher] "+r" (adv_cipher)::);

	offset += adv_cipher + 2;
	compression = get_data(ctx, offset, 1);
	if (!compression) {
		tls->flags |= TLS_COMPRESSION_ERROR;
		return -EIO;
	}

	if (client)
		adv_compression = *compression;
	else
		adv_compression = 0;

	compiler_barrier();
	adv_compression &= 0x7f;
	if (adv_compression > 255) {
		tls->flags |= TLS_COMPRESSION_TOO_LARGE;
		return -EIO;
	}

	offset += adv_compression + 1;
	// pull in 2B of header plus 4B of first extension
	extension = get_data(ctx, offset, 6);
	if (!extension) {
		tls->flags |= TLS_EXT_ERROR;
		return -EIO;
	}

	extlength = *(u16 *)extension;
	extlength = bpf_htons(extlength);
	extlength += 2;
	asm volatile (
		"if %[extlength] > 4 goto +1;\n"
		"%[extlength] = 0;\n"
		: [extlength] "+r"(extlength)::);
	extension = get_data(ctx, offset, extlength);
	if (!extension) {
		tls->flags |= TLS_EXT_ERROR;
		return -EIO;
	}
	data_end = (void *)(long)ctx->data_end;
	extension = (void *)extension + 2;
	TWENTY_EXTENSIONS
	tls->flags |= TLS_MAX_TLVS;
extension_macro_out:
	return maxlength;
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
#ifdef SK_MSG
int bpf_parse_tls(struct sk_msg_md *ctx,
		  void *payload, int dummy,
		  struct msg_tls *tls)
{
	int payload_off = 0;
#elif defined(SK_SKB)
int bpf_parse_tls(struct __sk_buff *ctx,
		  void *payload, int dummy,
		  struct msg_tls *tls)
{
	int payload_off = 0;
#else
int bpf_parse_tls(struct __sk_buff *ctx,
		  void *payload, int payload_off,
		  struct msg_tls *tls)
{
#endif
	void *data_end = (void *)(long)ctx->data_end;
	struct tls_hdr *hdr;
	int next = 0;

	if (payload + sizeof(struct tls_hdr) > data_end) {
		payload = get_data(ctx, payload_off, sizeof(struct tls_hdr));
		if (!payload)
			return -1;
		data_end = (void *)(long)ctx->data_end;
	}
	hdr = (struct tls_hdr *)payload;

	tls->type    = hdr->type;
	tls->length  = hdr->length;
	tls->version = hdr->version;

	if (hdr->type == TLS_TYPE_HANDSHAKE) {
		struct tls_handshake_hdr *handshake;
		bool client = false;

		if (payload + sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr) > data_end) {
			payload = get_data(ctx, payload_off, sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr));
			if (!payload)
				return -1;
		}
		handshake = (struct tls_handshake_hdr *)(payload + sizeof(struct tls_hdr));
		tls->subtype = handshake->type;
		tls->version = handshake->version;
		switch (handshake->type) {
		case client_hello:
			client = true;
		case server_hello:
			next = bpf_parse_tls_client_hello(ctx, payload_off, tls, client);
			break;
		default:
			break;
		}
	} else if (hdr->type == TLS_TYPE_ALERT) {
		struct tls_alert *tls_alert;

		if (payload + sizeof(struct tls_hdr) + sizeof(struct tls_alert) > data_end) {
			payload = get_data(ctx, payload_off, sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr));
			if (!payload)
				return -1;
		}
		tls_alert = (struct tls_alert *)(payload + sizeof(struct tls_hdr));
		tls->alert_level = tls_alert->level;
		tls->alert_description = tls_alert->description;
		/* Advance pointer to end of alert */
		next = sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr);
	}
	return next;
}

#define ETH_P_IP 0x800
#define TLS_REMOTE_PORT 0xBB01

#ifdef SK_MSG
static inline __attribute__((always_inline))
void skb_tls_key(struct sk_msg_md *skmsg, struct msg_tls_ipv4 *key) {
	key->daddr = skmsg->remote_ip4;
	key->saddr = skmsg->local_ip4;
	key->proto = 0;
	key->dport = TLS_REMOTE_PORT;
	key->sport = skmsg->local_port;
}
#elif defined(SK_SKB)
static inline __attribute__((always_inline))
void sk_skb_tls_key(struct __sk_buff *skb, struct msg_tls_ipv4 *key)
{
	key->daddr = skb->remote_ip4;
	key->saddr = skb->local_ip4;
	key->proto = 0;
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
	key->proto = 0;

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

/* TLS Certificate Error Codes */
#define ENEXTTOOLARGE	1
#define EGETDATA	2
#define ENOBUFFER	3
#define ECOPYERROR	4

/* TLS Certificate Hdr offset */
#define TLS_HEADER_BYTES 9

/* TBD: JF, extend verifier to understand void functions */
#ifndef SK_MSG
static inline __attribute__((always_inline))
int bpf_skskb_post_cert(struct __sk_buff *skb, struct msg_tls *event, int next, __u32 *cb0)
{
	void *data, *data_end = (void *)(long)skb->data_end;
	void *tls_server_hello = (void*)(long)skb->data;
	struct tls_handshake_certificate *cert;
	int *length, copied, remaining = 0, zero = 0, errout[2];
	__u32 csize = 0;
	__u8 *buffer;

	next += TLS_HEADER_BYTES; // Account for TLS Server Hello header
	if (next > 4096) {
		errout[1] = ENEXTTOOLARGE;
		goto out;
	}

	asm volatile ("%[next] &= 0x0fff;\n": [next] "+r"(next)::);
	data = (void*)tls_server_hello + next;
	if (data + sizeof(struct tls_handshake_certificate) > data_end) {
		data = get_data(skb, next, sizeof(struct tls_handshake_certificate));
		if (!data) {
			errout[1] = EGETDATA;
			goto out;
		}
		data_end = (void *)(long)skb->data_end;
	}
	compiler_barrier();
	cert = (struct tls_handshake_certificate *)data;
	csize = cert->length;
	csize = bpf_ntohs(csize);
	csize += 4 + 1;
	asm volatile ("%[csize] &= 0x0fff;\n": [csize] "+r"(csize)::);

	/* We get away with posting without a header because we have
	 * a flag above indicating the cert is the next event and this
	 * is a non-preemptive hook so we can be certain the user side
	 * will in-fact get this event immediately after above.
	 */
	buffer = map_lookup_elem(&tls_heap, &zero);
	if (!buffer) {
		errout[1] = ENOBUFFER;
		goto out;
	}

	if (data + csize > data_end) {
		int needed = csize + next;

		if (needed > skb->len) {
			needed = skb->len - next;
			event->type = TLS_TYPE_MORE_DATA;
			remaining = csize - needed;
		}
		asm volatile ("%[needed] &= 0x0fff;\n": [needed] "+r"(needed)::);
		asm volatile ("%[next] &= 0x0fff;\n": [next] "+r"(next)::);
		data = get_data(skb, next, needed);
		if (!data) {
			errout[1] = EGETDATA;
			goto out;
		}
		csize = needed;
		data_end = (void *)(long)skb->data_end;
	}

	/* It seems compiler and verifier are conspiring to reject my
	 * copy code. So loops generate code that wont prune and exceeds
	 * 1mil insn similarly unrolled loops do as well. So brute force
	 * this and macro it out and put code we want in via asm.
	 *
	 * The extra asm bounding logic is needed because csize may be
	 * reset above and seems 4.19 kernels are unable to track that
	 * the bound will be bounded with min value.
	 */
	asm volatile ("%[csize] &= 0x0fff;\n": [csize] "+r"(csize)::);
	copied = large_ctx_copy(skb, next, 0, csize);

	/* total bound clamp because verifier lost it from above :( */
	asm volatile ("%[copied] &= 0x0fff;\n": [copied] "+r"(copied)::);
	length = (int *)buffer;
	*length = copied;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, buffer, copied);
	if (csize > copied) {
		event->type = TLS_TYPE_MORE_DATA;
		*cb0 = next + copied;
		remaining += csize - copied;
	} else  {
		*cb0 = 0;
	}
	return remaining;
out:
	/* userspace wants to see an event so we generate an error event */
	errout[0] = 0;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, errout, sizeof(errout));
	return 0;
}

static inline __attribute__((always_inline))
int bpf_skskb_post_more_cert(struct __sk_buff *skb, struct msg_tls *event, int next, int bytes)
{
	void *data, *data_end = (void *)(long)skb->data_end;
	void *more_data = (void*)(long)skb->data;
	int *length, copy = bytes, zero = 0, errout[2];
	__u8 *buffer;

	buffer = map_lookup_elem(&tls_heap, &zero);
	if (!buffer) {
		errout[1] = ENOBUFFER;
		goto out;
	}

	if (next > 4096) {
		errout[1] = ENEXTTOOLARGE;
		goto out;
	}
	event->type = 0;
	asm volatile ("%[next] &= 0x0fff;\n": [next] "+r"(next)::);
	asm volatile ("%[copy] &= 0x0fff;\n": [copy] "+r"(copy)::);
	data = (void*)more_data + next + copy;
	if (data > data_end) {
		int needed = copy;

		if (next + needed > skb->len) {
			needed = skb->len - next;
			event->type = TLS_TYPE_MORE_DATA;
		}
		data = get_data(skb, next, needed);
		if (!data) {
			errout[1] = EGETDATA;
			goto out;
		}
		copy = needed;
		data_end = (void *)(long)skb->data_end;
	}

	/* It seems compiler and verifier are conspiring to reject my
	 * copy code. So loops generate code that wont prune and exceeds
	 * 1mil insn similarly unrolled loops do as well. So brute force
	 * this and macro it out and put code we want in via asm.
	 */
	copy = large_ctx_copy(skb, next, 4, copy);
	/* total bound clamp because verifier lost it from above :( */
	asm volatile ("%[copy] &= 0x0fff;\n": [copy] "+r"(copy)::);
	length = (int *)buffer;
	*length = copy;
	copy += 4;
	asm volatile ("%[copy] &= 0x0fff;\n": [copy] "+r"(copy)::);
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, buffer, copy);
	return bytes - copy + 4; // be careful to account for copy+=4 above
out:
	/* userspace wants to see an event so we generate an error event */
	errout[0] = 0;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, errout, sizeof(errout));
	return 0;
}
#endif
