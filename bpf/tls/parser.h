#include "api.h"

struct tls_hdr {
	__u8  type;
	__u16 version;
	__u16 length;
} __attribute__((packed));

struct tls_random {
	__u32 gmt_unix_time;
	__u8  random[28];
} __attribute__((packed));

struct tls_handshake_hdr {
	__u32 type:8;
	__u16 length;
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

#define TLS_TYPE_HANDSHAKE 22

#define TLS_VERSION_13 0x0403
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_11 0x0203
#define TLS_VERSION_10 0x0103

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
	if (extension > payload + maxlength) {			   \
		goto extension_macro_out;			   \
	}							   \
	extension = bpf_parse_extension(extension, &extension_length, data_end, tls); \
	if (!extension)						   \
		goto extension_macro_out;			   \
	if ((int)extension_length < 0)				   \
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
int ext_copy(__u8 *sni, __u8 *end, __u8 *ext, __u32 copy)
{
	int len = copy, off = 0;
	uint64_t tmp, ptr;

	asm volatile (
		"%[len] &= 0xff;\n"
		"%[off] &= 0xff;\n"
		"%[ptr] = %[ext];\n"
		// Default abort case
		"if %[len] > 32 goto 1f;\n"
		// 32B case
		"if %[len] < 32 goto +14\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 32;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u64 *)(%[ptr] +0);\n"
		"*(u64 *)(%[sni] + 0) = %[tmp];\n"
		"%[tmp] = *(u64 *)(%[ptr] +8);\n"
		"*(u64 *)(%[sni] + 8) = %[tmp];\n"
		"%[tmp] = *(u64 *)(%[ptr] +16);\n"
		"*(u64 *)(%[sni] + 16) = %[tmp];\n"
		"%[tmp] = *(u64 *)(%[ptr] +24);\n"
		"*(u64 *)(%[sni] + 24) = %[tmp];\n"
		"%[sni] += 32;\n"
		"%[ptr] += 32;\n"
		"%[len] -= 32;\n"
		// 16B case
		"if %[len] < 16 goto +10\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 16;\n"
		"if %[tmp] > %[end] goto 1f\n"
		"%[tmp] = *(u64 *)(%[ptr] +0);\n"
		"*(u64 *)(%[sni] + 0) = %[tmp];\n"
		"%[tmp] = *(u64 *)(%[ptr] +8);\n"
		"*(u64 *)(%[sni] + 8) = %[tmp];\n"
		"%[sni] += 16;\n"
		"%[ptr] += 16;\n"
		"%[len] -= 16;\n"
		// 8B case
		"if %[len] < 8 goto +8\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 8;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u64 *)(%[ptr] +0);\n"
		"*(u64 *)(%[sni] + 0) = %[tmp];\n"
		"%[ptr] += 8;\n"
		"%[sni] += 8;\n"
		"%[len] -= 8;\n"
		// 4B case
		"if %[len] < 4 goto +8\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 4;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u32 *)(%[ptr] +0);\n"
		"*(u32 *)(%[sni] + 0) = %[tmp];\n"
		"%[len] -= 4;\n"
		"%[sni] += 4;\n"
		"%[ptr] += 4;\n"
		// 3B case
		"if %[len] < 3 goto +10;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 3;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u8 *)(%[ptr] +0);\n"
		"*(u8 *)(%[sni] + 0) = %[tmp];\n"
		"%[tmp] = *(u8 *)(%[ptr] +1);\n"
		"*(u8 *)(%[sni] + 1) = %[tmp];\n"
		"%[tmp] = *(u8 *)(%[ptr] +2);\n"
		"*(u8 *)(%[sni] + 2) = %[tmp];\n"
		"%[len] -= 3;\n"
		// 2B case
		"if %[len] < 2 goto +8;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 2;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u8 *)(%[ptr] +0);\n"
		"*(u8 *)(%[sni] + 0) = %[tmp];\n"
		"%[tmp] = *(u8 *)(%[ptr] +1);\n"
		"*(u8 *)(%[sni] + 1) = %[tmp];\n"
		"%[len] -= 2;\n"
		// 1B case
		"if %[len] < 1 goto +6;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 1;\n"
		"if %[tmp] > %[end] goto 1f;\n"
		"%[tmp] = *(u8 *)(%[ptr] +0);\n"
		"*(u8 *)(%[sni] + 0) = %[tmp];\n"
		"%[len] -= 1;\n"
		"1:;\n"
		: [tmp] "+r"(tmp),
		  [ptr] "+r"(ptr),
	 	  [off] "+r"(off),
		  [len] "+r"(len),
		  [sni] "+r"(sni),
		  [end] "+r"(end)
		:
		  [ext] "r"(ext):);
	return copy - len;
}

static inline __attribute__((always_inline))
struct tls_extension *bpf_parse_extension(struct tls_extension *extension, __u16 *max, void *data_end, struct msg_tls *tls)
{
	__u16 extlength, exttype;
	void *dst = 0;

	if ((void *)extension + 4 > data_end)
		return 0;

	extlength = bpf_htons(extension->length);
	exttype = bpf_htons(extension->type);
	*max -= extlength - 4;

	switch (exttype) {
	case EXT_SERVER_NAME:
		dst = tls->sni;
		break;
	case EXT_SUPPORTED_VERSION:
		dst = tls->supported_versions;
		break;
	}

	if (dst)
		ext_copy(dst, data_end, (void *)extension + 4, extlength);

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
#ifdef SK_MSG
void *get_data(struct sk_msg_md *ctx, int off, int needed)
{
	int err = msg_pull_data(ctx, 0, off + needed, 0);
#else
void *get_data(struct __sk_buff *ctx, int off, int needed)
{
	int err = skb_pull_data(ctx, off + needed);
#endif
	void *data_end, *data, *tmp;

	if (err)
		return 0;

	data_end = (void*)(long)ctx->data_end;
	data = (void*)(long)ctx->data;
	/* We need to advance the pointer to offset position and
	 * then compare the new ptr + needed bytes to ensure we
	 * haven't walked off the end of the pointer. But, order
	 * matters here. This will smash the range value on the
	 * packet and create a new ptrid. Consider,
	 *
	 * r3 = r2       // r2 is the data pkt pointer
	 * r3 += off     // oops r3 is a new pkt pointer because off is not
	 * r3 += needed  // required to be a const, so we have two pkts as
	 *               // far as verifier is concerned, r2 and r3
	 * if r3 > r1    // r1 is data_end so now r3 has a bounds, but r2
	 *               // does not share these bounds
	 * <--- snip --->
	 * derference r2 later and verifier will fail because
	 * we verified the bound on r3, but that is not the same
	 * pointer as r2. To fix get our order of ops correct,
	 *
	 * r2 += off     // off need not be constant here. If its
	 *               // not constant r2 will have a new pktid
	 * r3 = r2       // Now r3 is r2 from verifier side
	 * r3 += needed  // needed must be a fixed known constant, then
	 *               // r3 and r2 are still the same pktid
	 * if (r3 > r1)  // Now we have bounds on original r2 and r2!
	 */
	asm volatile (
		"%[data] += %[off];\n"
		"%[tmp] = %[data];\n"
		"%[tmp] += %[needed];\n"
		"if %[tmp] <= %[data_end] goto +1;\n"
		"%[data] = 0;\n"
		: [data] "+r"(data),
		  [tmp] "+r"(tmp),
		  [data_end] "+r"(data_end),
		  [off] "+r"(off),
		  [needed] "+r"(needed)
		::);

	return data;
}

static inline __attribute__((always_inline))
#ifdef SK_MSG
int bpf_parse_tls_client_hello(struct sk_msg_md *ctx, int payload_off, struct msg_tls *tls, bool client)
#else
int bpf_parse_tls_client_hello(struct __sk_buff *ctx, int payload_off, struct msg_tls *tls, bool client)
#endif
{
	__u16 *cipher_length, adv_cipher, extension_length;
	struct tls_handshake_client_hello *client_hello;
	__u8 *compression, adv_compression, adv_session;
	struct tls_extension *extension;
	volatile __u16 maxlength;
	void *payload, *data, *data_end;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	payload = data + payload_off;

	client_hello = payload + sizeof(struct tls_handshake_hdr);
	if ((void*)client_hello + sizeof(struct tls_handshake_client_hello) > data_end) {
		client_hello = get_data(ctx, payload_off, sizeof(struct tls_handshake_client_hello));
		if (!client_hello)
			return SK_PASS;
		data_end = (void *)(long)ctx->data_end;
	}

	/* If you (a) have lots of extensions and (b) don't put required extensions in
	 * the front of the list go away we may drop your packets for fun.
	 */
	maxlength = client_hello->length;
	maxlength &= 0x7fff;
	if (maxlength > 1000)
		maxlength = 1000;
	/* We need pruning logic to work when we walk packet layout so do a bounds check
	 * with max length here. If needed we pull in the data. If we really don't have the
	 * data cork until we get don't let users send us partial headers. Then max length
	 * should follow us around.
	 */
	if ((void *)client_hello + maxlength > data_end)
		return SK_PASS; // escape hatch too many tlvs!

	compiler_barrier();
	adv_session = client_hello->session_id_length;
	adv_session &= 0x7fff;

	cipher_length = (void *)client_hello + sizeof(struct tls_handshake_client_hello) + adv_session;
	if (cipher_length + 2 > data_end)
		return SK_PASS;

	if (client) {
		adv_cipher = *cipher_length;
		adv_cipher = bpf_htons(adv_cipher);
	} else {
		adv_cipher = 0;
	}

	adv_cipher &= 0x7fff;
	if (adv_cipher > 255)
		return SK_PASS;

	compression = (void *)cipher_length + adv_cipher + 2;
	if (compression + 1 > data_end)
		return SK_PASS;
	if (client)
		adv_compression = *compression;
	else
		adv_compression = 0;

	compiler_barrier();
	adv_compression &= 0x7f;
	if (adv_compression > 255)
		return SK_PASS;

	extension = (void *)compression + adv_compression + 1;
	if (extension + 2 > data_end)
		return SK_PASS;

	extension_length = *(u16 *)extension;
	extension = (void *)extension + 2;
	compiler_barrier();
	maxlength = 0x7fff;
	TWENTY_EXTENSIONS
	//EXTENSION
	// For now we just parse extensions until we walk off the end of the
	// packet so we just jump here when that happens.
extension_macro_out:
	return SK_PASS;
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
#ifdef SK_MSG
int bpf_parse_tls(struct sk_msg_md *ctx, void *payload, int payload_off, struct msg_tls *tls)
#else
int bpf_parse_tls(struct __sk_buff *ctx, void *payload, int payload_off, struct msg_tls *tls)
#endif
{
	struct tls_hdr *hdr;
	void *data_end = (void *)(long)ctx->data_end;

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
			if (payload)
				return -1;
		}
		handshake = (struct tls_handshake_hdr *)(payload + sizeof(struct tls_hdr));
		switch (handshake->type) {
		case client_hello:
			client = true;
		case server_hello:
			bpf_parse_tls_client_hello(ctx, payload_off, tls, client);
			break;
		case hello_request:
		case certificate:
		case server_key_exchange:
		case certificate_request:
		case server_hello_done:
		case certificate_verify:
		case client_key_exchange:
		case finished:
		default:
			break;
		}
	}
	return 0;
}

#define ETH_P_IP 0x800

#ifndef SK_MSG
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
	void *data_end = (void *)(long)skb->data_end;
	__u8 doff;

	/* offset of doff + 4B read */
	if ((void *)tcphdr + 16 > data_end) {
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
