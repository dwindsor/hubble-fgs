#pragma once

typedef enum _flags {
	ADDRESS_BLOCK = 0,
	ADDRESS_PERMIT = 1,
} flags;

typedef struct _address_subnet {
	union {
		uint32_t address4;
		uint8_t octet[4];
		uint32_t address16[4];
	};
	uint16_t from_port;
	uint16_t to_port;
	uint8_t subnet_mask;
	uint8_t flags;
} address_subnet;

struct msg_common {
	uint8_t op;
	uint8_t flags; // internal flags not exported
	uint8_t pad[2];
	uint32_t size;
	uint64_t ktime;
};

struct msg_ip_tuple {
	uint64_t saddr[2];
	uint64_t daddr[2];
	uint16_t dport;
	uint16_t sport;
	uint8_t proto;
	uint8_t send;
	uint8_t version_byte;
	uint8_t ipv6;
	uint64_t conn_id;
}; // All fields aligned so no 'packed' attribute.

struct connection_key {
	uint32_t pid;
	uint64_t daddr[2];
	uint16_t dport;
	uint16_t sport;
};

struct connection_entry {
	uint64_t socket_cookie;
	// 0 is for outbound (connect), 1 is for inbound (accept).
	uint32_t socket_flags;
};

struct msg_execve_key {
	uint32_t pid; // Process TGID
	uint8_t pad[4];
	uint64_t ktime;
}; // All fields aligned so no 'packed' attribute.

struct msg_socket_stats {
	uint64_t ktime;
	uint64_t create_time;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint32_t segs_in;
	uint32_t segs_out;
	uint32_t srtt;
	uint32_t retranssegs;
	uint64_t retransbytes;
	uint32_t zero_window;
	uint32_t sk_drops;
	uint64_t rtt_buckets[8];
	uint64_t rtt_sum;
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	uint64_t socket_cookie;
	uint32_t socket_flags;
	uint32_t pad;
	uint64_t version;
	uint64_t ps_version; // pseudo-socket version (used in UDP).
	uint64_t create_time; // only used on close events.
	uint64_t close_time; // only used on close events.
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_with_stats_event {
	struct msg_common common;
	struct msg_ip_tuple tuple;
	unsigned long int ret;
	struct msg_execve_key key;
	uint64_t socket_cookie;
	uint32_t socket_flags;
	uint32_t pad;
	uint64_t version;
	uint64_t ps_version; // pseudo-socket version (used in UDP).
	uint64_t create_time; // only used on close events.
	uint64_t close_time; // only used on close events.
	struct msg_socket_stats stats;
}; // All fields aligned so no 'packed' attribute.

struct addr4_lpm_trie {
	__u32 prefix;
	__u32 addr;
};

struct addr6_lpm_trie {
	__u32 prefix;
	__u32 addr[4];
};

struct lpm_endpoint_id_value {
	uint64_t id;
};

struct cfg_value {
	uint8_t udp_enabled;
	uint8_t reserved1;
	uint8_t reserved2;
	uint8_t reserved3;
	uint8_t reserved4;
	uint8_t reserved5;
	uint8_t pad[2];
};

#define SOCKFLAGS_TYPE_UNKNOWN 0x0
#define SOCKFLAGS_TYPE_CONNECT 0x1
#define SOCKFLAGS_TYPE_ACCEPT  0x2
#define SOCKFLAGS_TYPE_LISTEN  0x4