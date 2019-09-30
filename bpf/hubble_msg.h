/* Docker IDs are unique at first 12 characters -- tbd confirm */
#define DOCKER_ID_LENGTH 13

#define MAXARGS 5
#define ARGSIZE 32
#define PROGSIZE 64
#define TASK_COMM_LEN 128

/* Msg Types */
enum msg_ops {
	MSG_OP_UNDEF,
	MSG_OP_IPV4_TCPCONNECT,
	MSG_OP_MAX,
};

/* Msg Layout */
struct msg_common {
	__u8  op;
	__u8  pad[3];
};

struct msg_pid {
	__u32 pid;
	__u32 uid;
	char filename[PROGSIZE];
	char args[MAXARGS][ARGSIZE];
};

struct msg_ipv4_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u16 sport;
	__u8  proto;
	__u8  pad[7];
};

struct msg_k8s {
	__u32 net_ns;
	__u32 cid;
	__u64 cgrpid;
	char  docker_id[DOCKER_ID_LENGTH+1];
	char  pad[3];
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

struct event_execve {
	__u32 pid;
	char filename[PROGSIZE];
	char args[MAXARGS][ARGSIZE];
};

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_LRU_HASH];
	unsigned int (*key_size)[sizeof(__u32)];
	unsigned int (*value_size)[sizeof(struct event_execve)];
	unsigned int (*max_entries)[4096];
} execve_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) execve_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event_execve),
	.max_entries = 4095,
};
#endif

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})
