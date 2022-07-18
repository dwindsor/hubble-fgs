#include "vmlinux.h"
#include "hubble_msg.h"
#include "cookie.h"
#include "bpf_fd_to_sk.h"

#define FD_LOOKUP_SIGNAL 1024
#define S_IFMT		 00170000
#define S_IFSOCK	 0140000
#define AF_INET		 2
#define AF_INET6	 10

struct fd_lookup_config {
	uint32_t pid;
	uint32_t fd;
	uint64_t saddr[2];
	uint64_t daddr[2];
	uint16_t sport;
	uint16_t dport;
	uint16_t protocol;
	uint8_t state;
	uint8_t ipv6;
};

struct bpf_map_def __attribute__((section("maps"), used))
fd_lookup_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fd_lookup_config),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) int
__kprobe_check_kill_permission(struct pt_regs *ctx, bool pre56)
{
	struct task_struct *p = (struct task_struct *)ctx->dx;
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

	/* Check for our special signal */
	if ((int)ctx->di != FD_LOOKUP_SIGNAL)
		return 0;

	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;
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

	sk = fd_to_sk(p, config->fd, required_protocol, pre56, &read_ok,
		      &family);
	if (!sk)
		return 0;

	cookie = (u64)sk;

	value = execve_map_get_noinit(pid);
	if (!value)
		return 0;

	sockmap_process.key.pid = value->key.pid;
	sockmap_process.key.ktime = value->key.ktime;

	/* Store the socket even if family or protocol couldn't be read.
	 */
	map_update_elem(&socket_cookie_to_proc_map, &cookie, &sockmap_process,
			0);

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
