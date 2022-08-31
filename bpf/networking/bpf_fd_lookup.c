#include "vmlinux.h"
#include "hubble_msg.h"
#include "cookie.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

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

__attribute__((section("kprobe/check_kill_permission"), used)) int
kprobe_check_kill_permission(struct pt_regs *ctx)
{
	struct task_struct *p = (void *)ctx->dx;
	struct fd_lookup_config *config;
	int zero = 0;
	uint32_t pid;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fd;
	struct file *file;
	struct inode *f_inode;
	umode_t i_mode;
	struct socket *sock;
	struct sock *sk;
	u64 cookie;
	struct execve_map_value *process;
	u16 family;
	long family_ret;
	u16 required_protocol;
	u16 read_protocol;
	long proto_ret;

	/* Check for our special signal */
	if ((int)ctx->di != FD_LOOKUP_SIGNAL)
		return 0;

	config = map_lookup_elem(&fd_lookup_config_map, &zero);
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

	if (probe_read(&files, sizeof(files), _(&(p->files))) < 0)
		return 0;
	if (probe_read(&fdt, sizeof(fdt), _(&(files->fdt))) < 0)
		return 0;
	if (probe_read(&fd, sizeof(fd), _(&(fdt->fd))) < 0)
		return 0;
	if (probe_read(&file, sizeof(file), fd + config->fd) < 0)
		return 0;
	if (probe_read(&f_inode, sizeof(f_inode), _(&(file->f_inode))) < 0)
		return 0;
	if (probe_read(&i_mode, sizeof(i_mode), _(&(f_inode->i_mode))) < 0)
		return 0;
	if ((i_mode & S_IFMT) != S_IFSOCK)
		return 0;

	/* In a socket, the private_data in the struct file *is* the struct sock.
	 * See sock_from_file() in net/socket.c for confirmation.
	 */
	if (probe_read(&sock, sizeof(sock), _(&(file->private_data))) < 0)
		return 0;
	if (probe_read(&sk, sizeof(sk), _(&(sock->sk))) < 0)
		return 0;

	/* We only care about IPv4 and IPv6, but we also store the socket even if
	 * we can't read the family for some reason.
	 */
	family_ret = probe_read(&family, sizeof(family),
				_(&(sk->__sk_common.skc_family)));
	if (family_ret == 0 && (family != AF_INET && family != AF_INET6))
		return 0;

	/* We only care matching the supplied protocol, but we also store the socket even if
	 * we can't read the protocol for some reason.
	 */
	proto_ret = probe_read(&read_protocol, sizeof(read_protocol),
			       _(&(sk->sk_protocol)));
	if (proto_ret == 0 && read_protocol != required_protocol)
		return 0;

	/* We store the sk as the cookie because we can't use get_socket_cookie()
	 * here, even on >=5.10, as we're in a kprobe. If the cookie look up fails
	 * in the inet programs, then they will look up the sk instead and move
	 * the entry to the actual cookie
	 */
	cookie = (u64)sk;

	process = execve_map_get_noinit(pid);
	if (!process)
		return 0;

	map_update_elem(&socket_cookie_to_proc_map, &cookie, process, 0);

	if (family_ret != 0 || proto_ret != 0)
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
	config->protocol = read_protocol;
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
