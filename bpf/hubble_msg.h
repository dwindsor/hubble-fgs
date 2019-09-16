/* Docker IDs are unique at first 12 characters -- tbd confirm */
#define DOCKER_ID_LENGTH 12

/* Msg Types */
enum msg_ops {
	MSG_OP_UNDEF,
	MSG_OP_IPV4_TCPCONNECT,
	MSG_OP_MAX,
};

/* Msg Layout */
struct msg_common {
	__u64 timestamp;
	__u8  op;
};

struct msg_pid {
	__u32 pid;
	__u32 uid;
};

struct msg_ipv4_tuple {
	__u32 saddr;
	__u32 daddr;
	__u8  proto;
	__u16 dport;
	__u16 sport;
};

struct msg_k8s {
	unsigned int net_ns;
	__u64        cgrpid;
	char         docker_id[DOCKER_ID_LENGTH+1];
	int          cid;
};

// separate data structs for ipv4 and ipv6
struct msg_ipv4_tcp_connect {
	struct msg_common     common;
	struct msg_pid        pid;
	struct msg_ipv4_tuple tuple;
	struct msg_k8s	      kube;
};

struct event {
	int event;
};
