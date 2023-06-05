#ifndef _NETWORKMSG__
#define _NETWORKMSG__

#include "common.h"
#include "process.h"

/* Socket Flags */
#define SOCKFLAGS_TYPE_UNKNOWN 0x0
#define SOCKFLAGS_TYPE_CONNECT 0x1
#define SOCKFLAGS_TYPE_ACCEPT  0x2
#define SOCKFLAGS_TYPE_LISTEN  0x4

#define SOCKFLAGS_TYPE_MASK 0x7

// These fields are specified and aligned to roughly match up with
// struct msg_tls_ip in tlsmsg.h.
// proto + pad = 32bit remaining
// post_daddr + post_dport + pad2 = 64 bit uid
struct msg_ip_tuple {
	__u64 saddr[2];
	__u64 daddr[2];
	__u16 dport;
	__u16 sport;
	__u8 proto;
	__u8 pad[3];
	__u32 post_daddr;
	__u16 post_dport;
	__u16 pad2;
	__u8 ipv6;
	__u8 pad3[7];
}; // All fields aligned so no 'packed' attribute.

struct msg_socket_stats {
	__u64 ktime;
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
	__u64 latency_buckets[8];
	__u64 rtt_sum;
	__u64 latency_sum;
}; // All fields aligned so no 'packed' attribute.

// harmonise data structs for ipv4 and ipv6
struct msg_ip_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	__u64 socket_cookie;
	struct msg_socket_stats stats;
	__u32 socket_flags;
	__u32 pad;
	__u64 duration; // only used on close events.
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

struct msg_kfree_skb {
	struct msg_common common;
	struct msg_calltrace calltrace;
	struct msg_ip_tuple tuple;
} __attribute__((packed));

#endif // _NETWORKMSG__
