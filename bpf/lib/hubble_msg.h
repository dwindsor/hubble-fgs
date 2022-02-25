#ifndef __HUBBLE_MSG_
#define __HUBBLE_MSG_

/* These are your sizing variables. Because we are running in BPF and must
 * be bounded in terms of loop iterations and memory usage we have to set
 * worse case bounds.
 *
 * For tuning the following values can be easily changed with memory and
 * instruction count tradeoffs,
 *
 *  MAXARGS - more or less arguments on command line
 *  MAXARGLENGTH - max length of any individual arg
 *  BUFFER - this is the total number of bytes per pid consumed for args
 *
 * If buffer is full before maxargs and/or maxarglength is consumed then
 * processing stops.
 */

/* Docker IDs are unique at first 12 characters, but we want to get
 * 12chars plus any extra prefix used by the container environment.
 * Minikube for example prepends 'docker-' to the id. So lets copy
 * 32B and assume at least 12B of it is ID info.
 */
#define DOCKER_ID_LENGTH 32
/* Max number of args to parse */
#define MAXARGS 20
/* Max length of any given arg */
#define MAXARGLENGTH 100
/* This is the absolute buffer size for args and filenames including some
 * extra head room so we can append last args string to buffer. The extra
 * headroom is an unfortunate result of bounds on offset/size in
 * event_args_builder().
 *
 * For example given an offset bounds
 *
 *   offset <- (0, 100)
 *
 * We will read into the buffer using this offset giving a max offset
 * of eargs + 100.
 *
 *   args[offset] <- (0, 100)
 *
 * Now we want to read this with call 45 aka probe_read_str as follows,
 * where 'kernel_struct_arg' is the kernel data struct we are reading.
 *
 *   probe_read_str(args[offset], size, kernel_struct_arg)
 *
 * But we have a bit of a problem determining if 'size' is out of array
 * range. The math would be,
 *
 *   size = length - offset
 *
 * Giving the remainder of the buffer,
 *
 * args          offset             length
 *    |---------------|------------------|
 *
 *                    |-------size-------|
 *
 * But verifier math works on bounds so bounds analysis of size is the
 * following,
 *
 *   length = 1024
 *   offset = (0, 100)
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   size <- (924, 1124)
 *
 * And verifier throws an error because args[offset + size] with bounds
 * anaylsis,
 *
 *   args_(max)[100 + 1024] = args_(max)[1124]
 *
 * To circumvent this, at least until we teach the verifier about
 * dependent variables, create a maxarg value and pad arg buffer with
 * it. Giving a args buffer of size 'length + pad' with above bounds
 * analysis,
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   if size > pad goto done
 *   size <- (924, 1124) // 1124 < length + pad
 *
 * Phew all clear now?
 */
#define CWD_MAX 256
#define BUFFER 1024
#define SIZEOF_EVENT 32
#define PADDED_BUFFER (BUFFER + MAXARGLENGTH + SIZEOF_EVENT + SIZEOF_EVENT + CWD_MAX)
/* This is the usable buffer size for args and filenames. It is calculated
 * as the (BUFFER SIZE - sizeof(parent) - sizeof(curr) but unfortunately
 * preprocess doesn't know types so we do it manually without sizeof().
 */
#define ARGSBUFFER (BUFFER - SIZEOF_EVENT - SIZEOF_EVENT)
#define __ASM_ARGSBUFFER 976
#define ARGSBUFFERMASK (ARGSBUFFER - 1)
#define MAXARGMASK (MAXARG - 1)

#define FILTER_SIZE 4096

#define XSTR(s) STR(s)
#define STR(s) #s

/* Msg flags */
#define EVENT_UNKNOWN  0x00
#define EVENT_EXECVE   0x01
#define EVENT_EXECVEAT 0x02
#define EVENT_PROCFS   0x04
#define EVENT_TRUNC_FILENAME 0x08
#define EVENT_TRUNC_ARGS     0x10
#define EVENT_TASK_WALK      0x20
#define EVENT_MISS	     0x40
#define EVENT_NEEDS_AUID     0x80
#define EVENT_ERROR_FILENAME 0x100
#define EVENT_ERROR_ARGS     0x200
#define EVENT_NEEDS_CWD      0x400
#define EVENT_NO_CWD_SUPPORT 0x800
#define EVENT_ROOT_CWD	     0x1000
#define EVENT_ERROR_CWD	     0x2000
#define EVENT_CLONE	     0x4000
#define EVENT_ERROR_SOCK     0x8000
#define EVENT_DOCKER_NAME_ERR       0x010000
#define EVENT_DOCKER_KN_ERR	    0x020000
#define EVENT_DOCKER_SUBSYSCGRP_ERR 0x040000
#define EVENT_DOCKER_SUBSYS_ERR     0x080000
#define EVENT_DOCKER_CGROUPS_ERR    0x100000
#define EVENT_ERROR_MOUNT_POINTS	0x200000
#define EVENT_ERROR_PATH_COMPONENTS	0x400000

/* get_full_path flags */
#define UNRESOLVED_MOUNT_POINTS		0x01
#define UNRESOLVED_PATH_COMPONENTS	0x02

/* Msg Types */
enum msg_ops {
	MSG_OP_UNDEF = 0,
	MSG_OP_IPV4_TCPCONNECT = 1,
	MSG_OP_IPV4_TCPCONNECTRET = 2,
	MSG_OP_IPV4_BIND = 3,
	MSG_OP_IPV4_LISTEN = 4,
	MSG_OP_EXECVE = 5,
	MSG_OP_TLS = 6,
	MSG_OP_EXIT = 7,
	MSG_OP_IPV4_TCPCLOSE = 8,
	MSG_OP_IPV4_TCPACCEPT = 9,
	MSG_OP_CREDS = 10,
	MSG_OP_KFREE_SKB = 11,
	MSG_OP_TLS_CONT = 12,
	MSG_OP_GENERIC_KPROBE = 13,
	MSG_OP_GENERIC_TRACEPOINT = 14,
	MSG_OP_IPV4_TCPSTATS = 15,
	MSG_OP_HTTP = 16,

	MSG_OP_IPV4_UDPCONNECT = 18,
	MSG_OP_IPV4_UDPPAYLOAD = 21,

	MSG_OP_MAX,

	// testing
	MSG_OP_TEST = 254,
};

#define EVENT_COMMON_FLAG_CLONE 0x01

/* Msg Layout */
struct msg_common {
	__u8  op;
	__u8 flags; // internal flags not exported
	__u8 pad[2];
	__u32 size;
	__u64 ktime;
};

/* Manually linked to ARGSBUFFER and PADDED_BUFFER if this changes then please
 * also changeo SIZEOF_EVENT.
 */
struct event_execve {
	__u32 size;
	__u32 pid;
	__u32 nspid;
	__u32 uid;
	__u32 auid;
	__u32 flags;
	__u64 ktime;
	char *args;
};

struct msg_pid {
	struct event_execve parent;
	struct event_execve curr;
};

struct msg_ipv4_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u16 sport;
	__u8  proto;
	__u32 post_daddr;
	__u16 post_dport;
	__u8  pad[5];
} __attribute__((packed));

struct msg_k8s {
	__u32 net_ns;
	__u32 cid;
	__u64 cgrpid;
	char  docker_id[DOCKER_ID_LENGTH];
} __attribute__((packed));

struct msg_calltrace {
	__u64 stack[16];
	int32_t ret;
} __attribute__((packed));

#define EXT_SERVER_NAME_LENGTH 64
#define EXT_VERSION_LENGTH 16

/* TLS Flags */
#define TLS_COPY_ERROR		  0x001
#define TLS_MAX_TLVS		  0x002
#define TLS_FRAME_TOO_LARGE	  0x004
#define TLS_HELLO_MSG_MISS	  0x008
#define TLS_CIPHER_ERROR	  0x010
#define TLS_CIPHER_TOO_LARGE	  0x020
#define TLS_COMPRESSION_ERROR     0x040
#define TLS_COMPRESSION_TOO_LARGE 0x080
#define TLS_EXT_ERROR		  0x100
#define TLS_EXT_TOO_LARGE	  0x200
#define TLS_VERSION		  0x400
#define TLS_CERT		  0x800
#define TLS_HANDSHAKE_MSG_MISS    0x1000

#define TLS_HTTP_VERSION          0xFFFF

/* Socket Flags */
#define SOCKFLAGS_TYPE_UNKNOWN	0x0
#define SOCKFLAGS_TYPE_CONNECT	0x1
#define SOCKFLAGS_TYPE_ACCEPT	0x2
#define SOCKFLAGS_TYPE_LISTEN	0x4

#define SOCKFLAGS_TYPE_MASK	0x7

/* A length-value, with a fixed max length. */
#define FLV(max_len) \
	struct { \
		__u8 length; \
		__u8 value[(max_len)]; \
	}

#define FLV_COPY(_tlv, _from, _len) do { \
	(_tlv).length = (_len); \
        memcpy((_tlv).value, (_from), sizeof((_tlv).value)); \
} while(0)

struct msg_tls {
	__u16 version;
	__u16 length;
	__u8 type;
	__u8 subtype;
	__u16 negotiated_version;
	__u32 flags;
	__u32 bytes;
	__u8  alert_level;
	__u8  alert_description;

	FLV(64) flv_session_id;
	FLV(64) flv_cipher;
	FLV(EXT_SERVER_NAME_LENGTH) flv_sni;
	FLV(EXT_VERSION_LENGTH) flv_supported_versions;
} __attribute__((packed));

struct msg_execve_key {
	__u32 pid;
	__u8  pad[4];
	__u64 ktime;
} __attribute__((packed));

struct msg_capabilities {
	__u64 permitted;
	__u64 effective;
	__u64 inheritable;
};

struct exit_info {
	__u32 code;
	__u32 pad;
};

struct msg_exit {
	struct msg_common common;
	struct msg_execve_key current;
	struct exit_info info;
};

struct msg_creds {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_capabilities caps;
};

struct msg_ns {
	__u32 uts_inum;
	__u32 ipc_inum;
	__u32 mnt_inum;
	__u32 pid_inum;
	__u32 pid_for_children_inum;
	__u32 net_inum;
	__u32 time_inum;
	__u32 time_for_children_inum;
	__u32 cgroup_inum;
	__u32 user_inum;
};

static inline __attribute__((always_inline))
size_t generic_kprobe_common_size()
{
	return sizeof(struct msg_common)
		+ sizeof(struct msg_execve_key)
		+ sizeof(struct msg_ns)
		+ sizeof(__u64) + sizeof(__u64) + sizeof(__u64);
}

#define MAX_POSSIBLE_ARGS 5
#define MAX_POSSIBLE_SELECTORS 31
#define SELECTORS_ACTIVE 31
#define MAX_CONFIGURED_SELECTORS MAX_POSSIBLE_SELECTORS + 1

struct msg_generic_kprobe {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_ns ns;
	__u64 id;
	__u64 thread_id;
	__u64 action;
	char args[24000];
	unsigned long a0,a1,a2,a3,a4;
	long argsoff[MAX_POSSIBLE_ARGS];
	__u64 curr;
	__u64 pass;
	bool active[MAX_CONFIGURED_SELECTORS];
};

struct msg_test {
	struct msg_common common;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
} __attribute__((packed));

struct msg_execve_event {
	struct msg_common	common;
	struct msg_k8s		kube;
	struct msg_execve_key	parent;
	__u64			parent_flags;
	struct msg_capabilities caps;
	struct msg_ns		ns;
	char			pid[PADDED_BUFFER];
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
} __attribute__((packed));

// separate data structs for ipv4 and ipv6
struct msg_ipv4_event {
	struct msg_common     common;
	struct msg_ipv4_tuple tuple;
	unsigned long int     ret;
	struct msg_execve_key key;
	__u64                 socket_cookie;
	struct msg_socket_stats stats;
	__u32                 socket_flags;
	__u32                 pad;
} __attribute__((packed));

struct msg_ipv4_key {
	__u32 pid;
	__u32 saddr;
	__u16 sport;
	__u16 pad;
} __attribute__((packed));

/* For HTTP users of msg_tls_ipv4 we set remaining field
 * to the direction. Either sender (HTTP_SEND) or receiver
 * (HTTP_RECV).
 */
#define HTTP_SEND 0
#define HTTP_RECV 1

struct msg_tls_ipv4 {
	__u32 saddr;
	__u32 daddr;
	/* Both ports are in host byte-order */
	__u16 dport;
	__u16 sport;
	__u32 remaining;
	__u64 uid;
} __attribute__((packed));

#define SOCKET_TLS_DONE 0x0001

struct msg_tls_event {
	struct msg_common     common;
	struct msg_tls_ipv4   tuple;
	struct msg_tls	      clienthello;
	struct msg_tls	      serverhello;
	struct msg_execve_key execve;
} __attribute__((packed));

struct msg_tls_cont_event {
	__u8 op;
	struct msg_tls_ipv4 tuple;
	__u32 payload_size; /* Payload size, or if zero an error follows */
	__u8 payload[0];
} __attribute__((packed));

struct msg_kfree_skb {
	struct msg_common common;
	struct msg_calltrace calltrace;
	struct msg_ipv4_tuple tuple;
} __attribute__((packed));

struct event {
	int event;
};

struct execve_map_value {
	struct msg_execve_key key;
	struct msg_execve_key pkey;
	__u32  flags;
	__u32 nspid;
	__u32 binary;
	__u32 pad;
} __attribute__((packed));

struct socketmap_value {
	struct msg_execve_key key;
	__u32 zero_window;
	__u32 socket_flags;
};

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

/* tracepoint args */
struct sched_execve_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int filename;
	int pid;
	int old_pid;
};

#ifndef ALIGNCHECKER
struct bpf_map_def __attribute__((section("maps"), used)) names_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(char) * 256,
	.value_size = sizeof(__u32),
	.max_entries = 64,
};

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
	unsigned int (*key_size)[sizeof(__u32)];
	unsigned int (*value_size)[sizeof(struct msg_execve_event)];
	unsigned int (*max_entries)[1];
} execve_msg_heap_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) execve_msg_heap_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_execve_event),
	.max_entries = 1,
};
#endif // BTF

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_HASH];
	unsigned int (*key_size)[sizeof(__u32)];
	unsigned int (*value_size)[sizeof(struct execve_map_value)];
	unsigned int (*max_entries)[32768];
} execve_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) execve_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct execve_map_value),
	.max_entries = 32768,
};
#endif // BTF

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
	unsigned int (*key_size)[sizeof(int)];
	unsigned int (*value_size)[sizeof(struct event)];
} tcpmon_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) tcpmon_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct event),
};
#endif // BTF

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_HASH];
	unsigned int (*key_size)[sizeof(struct msg_tls_ipv4)];
	unsigned int (*value_size)[sizeof(struct socketmap_value)];
	unsigned int (*max_entries)[32768];
} socket_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) socket_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct socketmap_value),
	.max_entries = 32768,
};
#endif // BTF

struct bpf_map_def __attribute__((section("maps"), used)) execve_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(__s64),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) socket_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(__s64),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) tls_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(__s64),
	.max_entries = 1,
};
#endif // ALIGNCHECKER

#ifndef bpf_ntohs
#define bpf_ntohs(x)		__builtin_bswap16(x)
#endif

#ifndef bpf_htons
#define bpf_htons(x)		__builtin_bswap16(x)
#endif

#ifndef bpf_ntohl
#define bpf_ntohl(x)		__builtin_bswap32(x)
#endif

#ifndef bpf_htonl
#define bpf_htonl(x)		__builtin_bswap32(x)
#endif
#endif // __HUBBLE_MSG_
