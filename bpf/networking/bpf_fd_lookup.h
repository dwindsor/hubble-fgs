#include "vmlinux.h"
#include "hubble_msg.h"
#include "cookie.h"
#include "bpf_fd_to_sk.h"
#include "../lib/address_family.h"
#include "bpf_tracing.h"
#include "bpf_network_helpers.h"

#define S_IFMT	 00170000
#define S_IFSOCK 0140000

struct fd_lookup_config {
	uint32_t pid;
	uint32_t fd;
	uint64_t sockaddr;
	uint64_t saddr[2];
	uint64_t daddr[2];
	uint16_t sport;
	uint16_t dport;
	uint16_t protocol;
	uint8_t state;
	uint8_t ipv6;
	uint8_t discover_proto_shift;
	uint8_t proto_shift;
	uint8_t signal_hit;
	uint8_t pad1;
	uint32_t pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fd_lookup_config);
	__uint(max_entries, 1);
} fd_lookup_config_map SEC(".maps");

static inline __attribute__((always_inline)) int
__kprobe_proc_task_name(struct pt_regs *ctx)
{
	struct task_struct *p = (struct task_struct *)PT_REGS_PARM2_CORE(ctx);
	struct fd_lookup_config *config;
	int zero = 0;
	uint32_t pid;
	struct sock *sk;
	u64 cookie;
	struct execve_map_value *value;
	struct socketmap_value sockmap_process = { 0 };
	u16 required_protocol;
	bool read_ok = false;
	u16 family = 0;
	int sk_err = 0;

	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;
	config->signal_hit = 1;

	/* The config specifies the protocol to care about */
	required_protocol = config->protocol;

	/* Clear the protocol in the config to indicate the socket doesn't
	 * match. This will be completed later if a valid socket matches.
	 */
	config->protocol = 0;

	if (probe_read(&pid, sizeof(pid), _(&(p->tgid))) < 0)
		return 0;
	if (config->pid != pid)
		return 0;

	sk_err = fd_to_sk(&sk, p, config->fd, required_protocol, &read_ok, &family,
			  config->discover_proto_shift, &config->proto_shift);
	switch (sk_err) {
	case FD_TO_SK_SUCCESS:
		if (config->discover_proto_shift) {
			/* Reset config->discover_proto_shift to indicate that we have
				* at least attempted to discover the protocol shift. If we failed
				* the proto_shift will be set to PROTO_SHIFT_UNKNOWN.
				*/
			config->discover_proto_shift = 0;
			/* Nothing else to do! */
			return 0;
		}
		break;
	case FD_TO_SK_INVALID_PTRS:
		/* This should never happen. */
		return 0;
	case FD_TO_SK_READ_ERROR_OTHER:
	case FD_TO_SK_READ_ERROR_FILE:
	case FD_TO_SK_READ_ERROR_INODE: {
		u64 reason = sk_err;
		emit_ip_error_event(ctx, 0, &reason, 0, IP_ERROR_SOCKET_DISCOVERY_READ_ERROR);
		return 0;
	}
	case FD_TO_SK_WRONG_FAMILY:
	case FD_TO_SK_WRONG_PROTO:
		/* An incorrect family or protocol does not mean a failure, but just
			 * that the socket didn't meet our expectations.
			*/
		return 0;
	case FD_TO_SK_NO_SK:
		emit_ip_error_event(ctx, 0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_NO_SK);
		return 0;
	}
	if (!sk) {
		emit_ip_error_event(ctx, 0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_NO_SK);
		return 0;
	}

	cookie = (u64)sk;

	value = execve_map_get_noinit(pid);
	if (!value) {
		emit_ip_error_event(ctx, 0, &cookie, 0,
				    IP_ERROR_SOCKET_DISCOVERY_NO_PROCESS);
		return 0;
	}

	sockmap_process.key.pid = value->key.pid;
	sockmap_process.key.ktime = value->key.ktime;

	// Store the create time as the current time (e.g. Tetragon start up time).
	// This is far from perfect, but at least the discovered flag will indicate
	// how we found this create time in case we want to exclude these.
	sockmap_process.create_time = ktime_get_ns();

	/* Store the socket even if family or protocol couldn't be read.
	*/
	add_socketmap(&cookie, 0, &sockmap_process);

	/* If we can't read the address family or protocol, then we can't
	 * report the socket.
	 */
	if (!read_ok)
		return 0;

	/* Pass the details of the socket back via the config map so that an 
	 * appropriate event can be generated. We don't use the usual ring
	 * buffer here because this preceeds the event handlers being
	 * established.
	 */
	probe_read(&config->sport, sizeof(config->sport),
		   _(&(sk->__sk_common.skc_num)));
	probe_read(&config->dport, sizeof(config->dport),
		   _(&(sk->__sk_common.skc_dport)));
	probe_read(&config->state, sizeof(config->state),
		   (const void *)_(&(sk->__sk_common.skc_state)));
	config->protocol = required_protocol;
	config->sockaddr = cookie;
	if (family == AF_INET) {
		config->ipv6 = 0;
		config->saddr[0] = 0;
		config->saddr[1] = 0;
		config->saddr[0] = 0;
		config->saddr[1] = 0;
		probe_read(&config->saddr[0], sizeof(uint32_t),
			   _(&(sk->__sk_common.skc_rcv_saddr)));
		probe_read(&config->daddr[0], sizeof(uint32_t),
			   _(&(sk->__sk_common.skc_daddr)));
	} else {
		config->ipv6 = 1;
		probe_read(config->saddr, sizeof(config->saddr),
			   _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read(config->daddr, sizeof(config->daddr),
			   _(&(sk->__sk_common.skc_v6_daddr)));
	}

	return 0;
}
