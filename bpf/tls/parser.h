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


struct tls_extension {
	__u16 type;
	__u16 length;
} __attribute__((packed));

#define TLS_TYPE_HELLO 22

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
	if (extension > data + maxlength) {			   \
		goto extension_macro_out;			   \
	} \
	extension = bpf_parse_extension(extension, maxlength, data_end, tls); \
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
struct tls_extension *bpf_parse_extension(struct tls_extension *extension, __u16 max, void *data_end, struct msg_tls *tls)
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
int bpf_parse_tls_client_hello(struct sk_msg_md *msg, struct msg_tls *tls)
{
	struct tls_handshake_client_hello *client_hello;
	__u8 *compression, adv_compression, adv_session;
	struct tls_extension *extension;
	__u16 *cipher_length, adv_cipher;
	volatile __u16 maxlength;
	void *data, *data_end;

	data_end = (void *)(long)msg->data_end;
	data = (void *)(long)msg->data;

	client_hello = data + sizeof(struct tls_handshake_hdr);
	if ((void*)client_hello + sizeof(struct tls_handshake_client_hello) > data_end)
		return SK_PASS;

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
	if ((void *)client_hello + maxlength > data_end) {
		int err = msg_pull_data(msg, 0, maxlength, 0);

		if (err)
			return SK_PASS;

		data_end = (void*)(long)msg->data_end;
		data = (void *)(long)msg->data;
		client_hello = data + sizeof(struct tls_handshake_hdr);
		if ((void *)client_hello + sizeof(struct tls_handshake_client_hello) > data_end)
			return SK_PASS;
	}

	compiler_barrier();
	adv_session = client_hello->session_id_length;
	adv_session &= 0x7fff;

	cipher_length = (void *)client_hello + sizeof(struct tls_handshake_client_hello) + adv_session;
	if (cipher_length + 2 > data_end)
		return SK_PASS;
	adv_cipher = *cipher_length;
	adv_cipher = bpf_htons(adv_cipher);

	adv_cipher &= 0x7fff;
	if (adv_cipher > 255)
		return SK_PASS;

	compression = (void *)cipher_length + adv_cipher + 2;
	if (compression + 1 > data_end)
		return SK_PASS;
	adv_compression = *compression;

	compiler_barrier();
	adv_compression &= 0x7f;
	if (adv_compression > 255)
		return SK_PASS;
	extension = (void *)compression + adv_compression + 3;
	compiler_barrier();
	maxlength = 0x7fff;
	TWENTY_EXTENSIONS
	// For now we just parse extensions until we walk off the end of the
	// packet so we just jump here when that happens.
extension_macro_out:
	return SK_PASS;
}

static inline __attribute__((always_inline))
int bpf_parse_tls_server_hello(struct sk_msg_md *msg)
{
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
int bpf_parse_tls(struct sk_msg_md *msg, struct msg_tls *tls)
{
	void *data, *data_end;
	struct tls_hdr *hdr;

	data_end = (void *)(long)msg->data_end;
	data = (void *)(long)msg->data;
	if (data + sizeof(struct tls_hdr) > data_end)
		return 0;
	hdr = (struct tls_hdr *)data;

	tls->type    = hdr->type;
	tls->length  = hdr->length;
	tls->version = hdr->version;

	if (hdr->type == TLS_TYPE_HELLO) {
		struct tls_handshake_hdr *handshake;

		if (data + sizeof(struct tls_hdr) + sizeof(struct tls_handshake_hdr) > data_end)
			return -1;
		handshake = (struct tls_handshake_hdr *)(data + sizeof(struct tls_hdr));
		switch (handshake->type) {
		case client_hello:
			bpf_parse_tls_client_hello(msg, tls);
			break;
		/* Everything below here is a nop for skmsg types */
		case hello_request:
			bpf_parse_tls_hello_request(msg);
			break;
		case server_hello:
			bpf_parse_tls_server_hello(msg);
			break;
		case certificate:
			bpf_parse_tls_certificate(msg);
			break;
		case server_key_exchange:
			bpf_parse_tls_server_key_exchange(msg);
			break;
		case certificate_request:
			bpf_parse_tls_certificate_request(msg);
			break;
		case server_hello_done:
			bpf_parse_tls_server_hello_done(msg);
			break;
		case certificate_verify:
			bpf_parse_tls_certificate_verify(msg);
		       break;
		case client_key_exchange:
			bpf_parse_tls_client_key_exchange(msg);
			break;
		case finished:
			bpf_parse_tls_finished(msg);
			break;
		default:
			break;
		}
	}
	return 0;
}
