// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _TLSMSG__
#define _TLSMSG__

#include "vmlinux.h"
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
#define FLV(max_len)                   \
	struct {                       \
		__u8 length;           \
		__u8 value[(max_len)]; \
	}

#define FLV_COPY(_tlv, _from, _len)                                  \
	do {                                                         \
		(_tlv).length = (_len);                              \
		memcpy((_tlv).value, (_from), sizeof((_tlv).value)); \
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

	FLV(64)
	flv_session_id;
	FLV(64)
	flv_cipher;
	FLV(EXT_SERVER_NAME_LENGTH)
	flv_sni;
	FLV(EXT_VERSION_LENGTH)
	flv_supported_versions;

	__u8 pad[2];
} __attribute__((packed));

#define SOCKET_TLS_DONE 0x0001

struct msg_tls_event {
	struct msg_common common;
	__u64 socket_cookie;
	__u64 socket_version;
	struct msg_tls clienthello;
	struct msg_tls serverhello;
	struct msg_execve_key execve;
} __attribute__((packed));

struct msg_tls_cont_event {
	__u8 op;
	__u64 socket_cookie;
	__u64 socket_version;
	__u32 payload_size; /* Payload size, or if zero an error follows */
	__u8 payload[0];
} __attribute__((packed));
#endif
