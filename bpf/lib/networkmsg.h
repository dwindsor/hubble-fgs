// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _NETWORKMSG__
#define _NETWORKMSG__

#include "vmlinux.h"
#include "common.h"
#include "process.h"

/* Socket Flags */
#define SOCKFLAGS_TYPE_UNKNOWN 0x0
#define SOCKFLAGS_TYPE_CONNECT 0x1
#define SOCKFLAGS_TYPE_ACCEPT  0x2
#define SOCKFLAGS_TYPE_LISTEN  0x4

#define SOCKFLAGS_TYPE_MASK 0x7

struct msg_ip_tuple {
	__u64 saddr[2];
	__u64 daddr[2];
	__u16 dport;
	__u16 sport;
	__u8 proto;
	__u8 send;
	__u8 version_byte;
	__u8 ipv6;
	__u32 post_daddr;
	__u16 post_dport;
	__u16 pad;
}; // All fields aligned so no 'packed' attribute.

struct msg_socket_stats {
	__u64 ktime;
	__u64 create_ktime;
	__u64 bytes_sent;
	__u64 bytes_received;
	__u32 segs_in;
	__u32 segs_out;
	__u64 bytes_submitted;
	__u64 bytes_consumed;
	__u32 segs_consumed;
	__u32 segs_submitted;
	__u32 srtt;
	__u32 retranssegs;
	__u64 retransbytes;
	__u32 tozerowin;
	__u32 sk_drops;
	__u32 skb_consume_misses;
	__u32 pad;
	__u64 rtt_buckets[8];
	__u64 rtt_sum;
	__u64 latency_buckets[8];
	__u64 latency_sum;
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	__u64 socket_cookie;
	__u32 socket_flags;
	__u32 version;
	__u64 duration; // only used on close events.
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_with_stats_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	__u64 socket_cookie;
	__u32 socket_flags;
	__u32 version;
	__u64 duration; // only used on close events.
	struct msg_socket_stats stats;
}; // All fields aligned so no 'packed' attribute.

struct msg_icmp_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	struct msg_execve_key key;
	__u64 socket_cookie;
	__u8 icmp_type;
	__u8 icmp_code;
	__u8 icmp_data[4];
	__u16 icmp_len;
	__u8 icmp_ip_proto;
	__u8 icmp_ip_ttl;
	__u16 icmp_ip_port;
	__u32 icmp_ip_pointer;
	__u64 icmp_gateway[2];
}; // All fields aligned so no 'packed' attribute.

struct msg_ipv4_key {
	__u32 pid;
	__u32 saddr;
	__u16 sport;
	__u8 pad[6];
}; // All fields aligned so no 'packed' attribute.

struct msg_process_network_watermarks_event {
	struct msg_common common;
	struct msg_execve_key key;
	__u32 protocol;
	__u8 direction;
	__u8 state;
	__u8 type;
	__u8 pad;
	__u64 window_size;
	__u64 hist_avg;
	__u64 hist_burst_trigger;
	__u64 hist_dip_trigger;
	__u64 window_avg;
};

// application_id specifies the specific application or protocol that this
// event refers to.
#define UDPSEQERR_APP_UNKNOWN 0
#define UDPSEQERR_APP_MTP     1

// app_specific_id can be used by any specified app in any way it chooses.
struct msg_udp_seq_error_event {
	struct msg_common common;
	struct msg_execve_key key;
	struct msg_ip_tuple tuple;
	__u64 socket_cookie;
	__u64 application_id;
	__u64 app_specific_id;
	__u64 seq_num_expected;
	__u64 seq_num_received;
}; // All fields aligned so no 'packed' attribute.

struct msg_calltrace {
	__u64 stack[16];
	int32_t ret;
} __attribute__((packed));

struct msg_kfree_skb {
	struct msg_common common;
	struct msg_calltrace calltrace;
	struct msg_ip_tuple tuple;
} __attribute__((packed));

#endif // _NETWORKMSG__
