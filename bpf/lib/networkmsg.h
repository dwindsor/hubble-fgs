#ifndef _NETWORKMSG__
#define _NETWORKMSG__

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
	__u32 post_daddr;
	__u16 post_dport;
	__u8 ipv6;
	__u8 pad[4];
} __attribute__((packed));

struct msg_socket_stats {
	__u64 bytes_sent;
	__u64 bytes_received;
	__u32 segs_in;
	__u32 segs_out;
	__u32 srtt;
	__u32 retranssegs;
	__u64 retransbytes;
	__u32 tozerowin;
	__u32 sk_drops;
	__u32 skb_consume_misses;
	__u64 buckets[8];
} __attribute__((packed));

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
} __attribute__((packed));

struct msg_ipv4_key {
	__u32 pid;
	__u32 saddr;
	__u16 sport;
	__u16 pad;
} __attribute__((packed));

struct msg_process_network_burst_event {
	struct msg_common common;
	struct msg_execve_key key;
	__u32 protocol;
	__u32 burst_start_dir;
	__u64 window_size;
	__u64 hist_avg;
	__u64 hist_trigger;
	__u64 window_avg;
};

struct msg_kfree_skb {
	struct msg_common common;
	struct msg_calltrace calltrace;
	struct msg_ip_tuple tuple;
} __attribute__((packed));

#endif // _NETWORKMSG__
