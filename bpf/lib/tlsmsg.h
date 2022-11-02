#ifndef _TLSMSG__
#define _TLSMSG__

#include "networkmsg.h"

/* Applying 'packed' attribute to structs causes clang to write to the
 * members byte-by-byte, as offsets may not be aligned. This is bad for
 * performance, instruction count and complexity, so don't apply this
 * attribute to structs where members are correctly aligned already
 * (e.g. by padding, layout).
 */

/* TLS Flags */
#define TLS_COPY_ERROR		  0x001
#define TLS_MAX_TLVS		  0x002
#define TLS_FRAME_TOO_LARGE	  0x004
#define TLS_HELLO_MSG_MISS	  0x008
#define TLS_CIPHER_ERROR	  0x010
#define TLS_CIPHER_TOO_LARGE	  0x020
#define TLS_COMPRESSION_ERROR	  0x040
#define TLS_COMPRESSION_TOO_LARGE 0x080
#define TLS_EXT_ERROR		  0x100
#define TLS_EXT_TOO_LARGE	  0x200
#define TLS_VERSION		  0x400
#define TLS_CERT		  0x800
#define TLS_HANDSHAKE_MSG_MISS	  0x1000

#define TLS_HTTP_VERSION 0xFFFF

#define EXT_SERVER_NAME_LENGTH 64
#define EXT_VERSION_LENGTH     16

/* A length-value, with a fixed max length. */
#define FLV(max_len)                                                           \
	struct {                                                               \
		__u8 length;                                                   \
		__u8 value[(max_len)];                                         \
	}

#define FLV_COPY(_tlv, _from, _len)                                            \
	do {                                                                   \
		(_tlv).length = (_len);                                        \
		memcpy((_tlv).value, (_from), sizeof((_tlv).value));           \
	} while (0)

struct msg_tls {
	__u16 version;
	__u16 length;
	__u8 type;
	__u8 subtype;
	__u16 negotiated_version;
	__u32 flags;
	__u32 bytes;
	__u8 alert_level;
	__u8 alert_description;

	FLV(64) flv_session_id;
	FLV(64) flv_cipher;
	FLV(EXT_SERVER_NAME_LENGTH) flv_sni;
	FLV(EXT_VERSION_LENGTH) flv_supported_versions;
} __attribute__((packed));

#define SOCKET_TLS_DONE 0x0001

// These fields are specified and aligned to roughly match up with
// struct msg_ip_tuple in networkmsg.h.
// remaining = proto + pad
// uid = post_daddr + post_dport + pad2
struct msg_tls_ip {
	__u64 saddr[2];
	__u64 daddr[2];
	/* Both ports are in host byte-order */
	__u16 dport;
	__u16 sport;
	__u32 remaining;
	__u64 uid;
	__u8 ipv6;
	__u8 pad[7];
}; // All fields aligned so no 'packed' attribute.

struct msg_tls_event {
	struct msg_common common;
	struct msg_tls_ip tuple;
	struct msg_tls clienthello;
	struct msg_tls serverhello;
	struct msg_execve_key execve;
} __attribute__((packed));

struct msg_tls_cont_event {
	__u8 op;
	struct msg_tls_ip tuple;
	__u32 payload_size; /* Payload size, or if zero an error follows */
	__u8 payload[0];
} __attribute__((packed));

static inline __attribute__((always_inline)) int
is_tuple_local(struct msg_tls_ip *tuple)
{
	return ((!tuple->ipv6 &&
		 ( // ipv4
			 (tuple->daddr[0] & 0xff) == 127 || // daddr lo addr
			 (tuple->saddr[0] & 0xff) == 127 || // saddr lo addr
			 tuple->daddr[0] ==
				 0)) || // listening socket no addr always local
		(tuple->ipv6 &&
		 ( // ipv6
			 (tuple->daddr[0] & 0xc0ff) == 0x80fe || // daddr lo addr
			 (tuple->saddr[0] & 0xc0ff) == 0x80fe || // saddr lo addr
			 (tuple->daddr[0] == 0 &&
			  tuple->daddr[1] ==
				  0))) // listening socket no addr always local
	);
}

#endif
