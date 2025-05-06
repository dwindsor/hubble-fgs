// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _ISO_MSG_TYPES_
#define _ISO_MSG_TYPES_

// TODO: remove
#include "../../modules/tetragon-oss/bpf/lib/msg_types.h"

/* Msg Types */
enum iso_msg_ops {
	ISO_MSG_OP_UNDEF = MSG_OP_UNDEF,
	ISO_MSG_OP_TCPCONNECT = 1,
	ISO_MSG_OP_TCPCONNECTRET = 2,
	ISO_MSG_OP_BIND = 3,
	ISO_MSG_OP_LISTEN = 4,
	ISO_MSG_OP_EXECVE = MSG_OP_EXECVE,
	ISO_MSG_OP_TLS = 6,
	ISO_MSG_OP_EXIT = MSG_OP_EXIT,
	ISO_MSG_OP_TCPCLOSE = 8,
	ISO_MSG_OP_TCPACCEPT = 9,
	ISO_MSG_OP_CREDS = 10,
	ISO_MSG_OP_KFREE_SKB = 11,
	ISO_MSG_OP_TLS_CONT = 12,
	ISO_MSG_OP_GENERIC_KPROBE = MSG_OP_GENERIC_KPROBE,
	ISO_MSG_OP_GENERIC_TRACEPOINT = MSG_OP_GENERIC_TRACEPOINT,
	ISO_MSG_OP_TCPSTATS = 15,
	ISO_MSG_OP_HTTP = 16,

	ISO_MSG_OP_UDPCLOSE = 17,
	ISO_MSG_OP_UDPCONNECT = 18,
	ISO_MSG_OP_UDPPAYLOAD = 21,

	ISO_MSG_OP_PROCESS_NETWORK_BURST = 22,

	ISO_MSG_OP_CLONE = MSG_OP_CLONE, // 23

	ISO_MSG_OP_DATA = MSG_OP_DATA, // 24

	ISO_MSG_OP_NETNS_EXIT = 25,

	ISO_MSG_OP_FILE = 129,

	ISO_MSG_OP_IP_ERROR = 130,

	ISO_MSG_OP_FILE_RENAME = 131,

	ISO_MSG_OP_PROCESS_NETWORK_WATERMARK = 132,

	ISO_MSG_OP_UDP_SEQ_ERROR = 133,

	ISO_MSG_OP_ICMP = 134,
	ISO_MSG_OP_ICMPV6 = 135,

	ISO_MSG_OP_UDPLISTEN = 136,

	ISO_MSG_OP_RAWSOCK_CREATE = 137,
	ISO_MSG_OP_RAWSOCK_CLOSE = 138,

	ISO_MSG_OP_FILE_LINK = 139,
	ISO_MSG_OP_FILE_SYMLINK = 140,
	ISO_MSG_OP_FILE_OPENRAW = 141,

	ISO_MSG_OP_MAX,

	ISO_MSG_OP_TEST = 254,
};
#endif // _ISO_MSG_TYPES_
