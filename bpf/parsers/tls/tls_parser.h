#ifndef tls_parser_h_INCLUDED
#define tls_parser_h_INCLUDED

#include "api.h"
#include "../parser.h"
#include "../bottle.h"
#include "tls_map.h"
#include "bpf_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct msg_tls_event);
	__uint(max_entries, 1);
} tls_heap SEC(".maps");

struct tls_hdr {
	__u8 type;
	__u16 version;
	__u16 length;
} __attribute__((packed));

struct tls_alert {
	__u8 level;
	__u8 description;
} __attribute__((packed));

struct tls_handshake_hdr {
	__u32 type : 8;
	__u32 length : 24;
	__u16 version;
} __attribute__((packed));

#define TLS_TYPE_MORE_DATA 1
#define TLS_TYPE_ALERT	   21
#define TLS_TYPE_HANDSHAKE 22

#define TLS_HANDSHAKE_TYPE_CERTIFICATE 11

#define TLS_VERSION_13 0x0403
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_11 0x0203
#define TLS_VERSION_10 0x0103

enum tls_parser_error {
	TLS_PARSE_ERROR = -1,
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

#define MAX_EXT_LENGTH	      255
#define EXT_SERVER_NAME	      0
#define EXT_SUPPORTED_VERSION 43
#define MAX_EXTS	      20

static inline __attribute__((always_inline)) int
bpf_parse_tls_client_hello(struct bottle *bottle, struct msg_tls *tls,
			   bool client)
{
	void *data_end;
	u16 length;
	u8 *data;

#define READ_BE16()                                                            \
	({                                                                     \
		u16 x = ((u16)*data) << 8 | *(data + 1);                       \
		data += 2;                                                     \
		x;                                                             \
	})
#define BOUNDS(val, flag, mask)                                                \
	({                                                                     \
		if ((val) > (mask)) {                                          \
			tls->flags |= flag;                                    \
			return TLS_PARSE_ERROR;                                \
		}                                                              \
		asm volatile("%1 &= " #mask ";\n" : "+r"(val)::);              \
	})

	length = bpf_ntohs(tls->length);
	data = bottle_get_data(bottle, sizeof(struct tls_hdr), length);
	if (!data)
		return TLS_PARSE_OUT_OF_DATA;

	BOUNDS(length, TLS_FRAME_TOO_LARGE, 0x1fff);
	data_end = data + length;

	/* Skip handshake header and the random bytes */
	data += 1 /* type */ + 3 /* length */ + 2 /* version */ +
		32 /* random */;

	/* Session ID */
	length = *data++;
	FLV_COPY(tls->flv_session_id, data, length);
	data += length;

	/* Cipher */
	if (client) {
		length = READ_BE16();
		BOUNDS(length, TLS_CIPHER_TOO_LARGE, 0xff);
		FLV_COPY(tls->flv_cipher, data, length);
		data += length;
	} else {
		FLV_COPY(tls->flv_cipher, data, 2);
		data += 2;
	}

	/* Compression */
	length = *data++;
	BOUNDS(length, TLS_COMPRESSION_TOO_LARGE, 0xff);
	data += length;

	/* Extensions */
	length = READ_BE16();
	BOUNDS(length, TLS_EXT_TOO_LARGE, 0xfff);
	if (data + length > data_end) {
		tls->flags |= TLS_EXT_TOO_LARGE;
		return TLS_PARSE_ERROR;
	}
	/* Constrain to end of extensions */
	data_end = data + length;

	relax_verifier();

	/* Find the SNI and supported versions extensions.
         * We do it this way to avoid doing too much work within
         * the unrolled loop in order to stay below the 4096
         * instruction limit of 4.x kernels. */
	u8 *ext_sni = 0;
	u16 ext_sni_len = 0;
	u8 *ext_ver = 0;
	u16 ext_ver_len = 0;
	int ext;

#pragma unroll
	for (ext = 0; ext < MAX_EXTS; ext++) {
		if (data + 2 > data_end)
			break;

		u16 ext_type = READ_BE16();
		length = READ_BE16();
		BOUNDS(length, TLS_EXT_TOO_LARGE, 0xff);

		u8 *start = data;
		data += length;

		if (ext_type == EXT_SERVER_NAME) {
			ext_sni = start;
			ext_sni_len = length;
		} else if (ext_type == EXT_SUPPORTED_VERSION) {
			ext_ver = start;
			ext_ver_len = length;

			/* SNI comes before supported versions according to
                         * spec, so we can stop when we find the version */
			break;
		}
	}

	/* Check that we didn't overflow. */
	if (data > data_end) {
		tls->flags |= TLS_EXT_TOO_LARGE;
		return TLS_PARSE_ERROR;
	}

	if (ext >= MAX_EXTS)
		tls->flags |= TLS_MAX_TLVS;

	if (ext_sni)
		FLV_COPY(tls->flv_sni, ext_sni, ext_sni_len);

	if (ext_ver) {
		tls->flags |= TLS_VERSION;
		FLV_COPY(tls->flv_supported_versions, ext_ver, ext_ver_len);
	}

	return 0;

#undef READ_BE16
#undef BOUNDS
}

static inline __attribute__((always_inline)) int
bpf_parse_tls_skb(struct __sk_buff *skb, struct msg_tls *tls)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
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
	copy = (struct tls_hdr *)payload;
	tls->type = copy->type;
	tls->length = copy->length;
	tls->version = copy->version;
	return 0;
}

static inline __attribute__((always_inline)) bool
is_tls_handshake(struct msg_tls *tls)
{
	return tls->type == TLS_TYPE_HANDSHAKE;
}

static inline __attribute__((always_inline)) bool
is_tls_client_hello_handshake(struct msg_tls *tls)
{
	return is_tls_handshake(tls) && tls->subtype == client_hello;
}

static inline __attribute__((always_inline)) bool
is_tls_server_hello_handshake(struct msg_tls *tls)
{
	return is_tls_handshake(tls) && tls->subtype == server_hello;
}

static inline __attribute__((always_inline)) bool
is_tls_version(struct msg_tls *tls)
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

static inline __attribute__((always_inline)) bool
is_tls_more_data(struct msg_tls *tls)
{
	return tls->type == TLS_TYPE_MORE_DATA;
}

static inline __attribute__((always_inline)) bool
is_expected_tls_data(struct msg_tls *tls)
{
	return is_tls_more_data(tls);
}

static inline __attribute__((always_inline)) bool
is_expected_tls_client_hello(struct msg_tls *tls)
{
	return is_tls_client_hello_handshake(tls) && is_tls_version(tls);
}

static inline __attribute__((always_inline)) bool
is_expected_tls_server_hello(struct msg_tls *tls)
{
	return is_tls_server_hello_handshake(tls) && is_tls_version(tls);
}

static inline __attribute__((always_inline)) int
bpf_parse_tls(struct bottle *bottle, struct msg_tls *tls)
{
	struct tls_hdr *hdr;
	int next = 0, err;
	void *payload;

	payload = bottle_get_data(bottle, 0, sizeof(struct tls_hdr));
	if (!payload)
		return TLS_PARSE_OUT_OF_DATA;

	hdr = (struct tls_hdr *)payload;

	tls->type = hdr->type;
	tls->length = hdr->length;
	tls->version = hdr->version;

	if (hdr->type == TLS_TYPE_HANDSHAKE) {
		struct tls_handshake_hdr *handshake;
		bool client = false;

		payload = bottle_get_data(
			bottle, 0,
			sizeof(struct tls_hdr) +
				sizeof(struct tls_handshake_hdr));
		if (!payload)
			return TLS_PARSE_OUT_OF_DATA;

		handshake =
			(struct tls_handshake_hdr *)(payload +
						     sizeof(struct tls_hdr));
		tls->subtype = handshake->type;
		tls->version = handshake->version;
		switch (handshake->type) {
		case client_hello:
			client = true;
			/* fallthrough */
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

		payload = bottle_get_data(
			bottle, 0,
			sizeof(struct tls_hdr) +
				sizeof(struct tls_handshake_hdr));

		if (!payload)
			return TLS_PARSE_OUT_OF_DATA;
		tls_alert =
			(struct tls_alert *)(payload + sizeof(struct tls_hdr));
		tls->alert_level = tls_alert->level;
		tls->alert_description = tls_alert->description;
		/* Advance pointer to end of alert */
		next = sizeof(struct tls_hdr) +
		       sizeof(struct tls_handshake_hdr);
	} else {
		return TLS_PARSE_ERROR;
	}

	return next;
}

#define ETH_P_IP	0x800
#define TLS_REMOTE_PORT 443

#if defined(SK_MSG)
static inline __attribute__((always_inline)) void
skmsg_tls_tuple(struct sk_msg_md *skmsg, struct msg_tls_ip *tuple)
{
	tuple->daddr[0] = skmsg->remote_ip4;
	tuple->daddr[1] = 0;
	tuple->saddr[0] = skmsg->local_ip4;
	tuple->saddr[1] = 0;
	tuple->ipv6 = 0;
	tuple->dport = bpf_htons(TLS_REMOTE_PORT);
	tuple->sport = skmsg->local_port;

	if (bpf_core_field_exists(skmsg->sk)) {
		tuple->dport = skmsg->sk->dst_port;
		tuple->sport = skmsg->sk->src_port;

		if (is_tuple_local(tuple))
			tuple->uid = msg_netns(skmsg);
	}
}
#elif defined(SK_SKB)
static inline __attribute__((always_inline)) void
skskb_tls_tuple(struct __sk_buff *skb, struct msg_tls_ip *tuple)
{
	struct bpf_sock *sk;

	tuple->daddr[0] = skb->remote_ip4;
	tuple->saddr[0] = skb->local_ip4;
	tuple->ipv6 = 0;
	sk = skb->sk;
	if (sk) {
		tuple->dport = skb->sk->dst_port;
		tuple->sport = skb->sk->src_port;

		if (is_tuple_local(tuple))
			tuple->uid = skskb_netns(skb);
	}
}
#else
static inline __attribute__((always_inline)) void *
skb_tls_tuple(struct __sk_buff *skb, int *off, struct msg_tls_ip *tuple)
{
	void *data, *data_end;
	struct tcphdr *tcphdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	__u8 tcp_off;
	__u16 proto;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	/* TBD soon data, data_end, payload will be streamified and and
	 * the extra data_end reset will be dropped.
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		eth = get_data(skb, 0,
			       sizeof(struct ethhdr) + sizeof(struct iphdr));
		if (!eth)
			return 0;
		data_end = (void *)(long)skb->data_end;
	}

	proto = eth->h_proto;
	if (proto != bpf_htons(ETH_P_IP))
		return 0;

	iphdr = (void *)eth + sizeof(struct ethhdr);
	tuple->daddr[0] = iphdr->daddr;
	tuple->saddr[0] = iphdr->saddr;
	tuple->ipv6 = 0;

	if (iphdr->protocol != IPPROTO_TCP)
		return 0;

	tcp_off = iphdr->ihl;
	tcp_off &= 0x0f;
	tcp_off *= 4;
	tcphdr = (void *)iphdr + tcp_off;
	if (tcphdr + sizeof(struct tcphdr) > data_end) {
		tcphdr = get_data(skb, sizeof(struct ethhdr) + tcp_off,
				  sizeof(struct tcphdr));
		if (!tcphdr)
			return 0;
		data_end = (void *)(long)skb->data_end;
	}

	tuple->dport = tcphdr->dest;
	tuple->sport = tcphdr->source;
	*off = tcp_off + sizeof(struct ethhdr);
	return (void *)tcphdr;
}

static inline __attribute__((always_inline)) void *
skb_tcp_payload(struct __sk_buff *skb, struct tcphdr *tcphdr, int *offset)
{
	void *data_end;
	__u8 doff;

	/* Under code refactor clang was putting a <<32,>>32 here to
	 * apparently zero up 32bits of data_end. But, this broke
	 * verifier on 4.19 kernels. Lets tell clang how to do this
	 * with asm.
	 */
	asm volatile("%[data_end] = *(u32*)%[skb_end];\n"
		     : [data_end] "+r"(data_end)
		     : [skb_end] "m"(skb->data_end)
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
	return (void *)tcphdr + doff;
}
#endif

#endif /* tls_parser_h_INCLUDED */
