#include "vmlinux.h"
#include "hubble_msg.h"
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

#define FD_LOOKUP_SIGNAL 1024
#define S_IFMT		 00170000
#define S_IFSOCK	 0140000

struct fd_lookup_config {
	uint32_t pid;
	uint32_t fd;
};

struct bpf_map_def __attribute__((section("maps"), used))
fd_lookup_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fd_lookup_config),
	.max_entries = 1,
};

__attribute__((section(("kprobe/check_kill_permission")), used)) int
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

	/* Check for our special signal */
	if ((int)ctx->di != FD_LOOKUP_SIGNAL)
		return 0;

	config = map_lookup_elem(&fd_lookup_config_map, &zero);
	if (!config)
		return 0;

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

	/* We store the sk as the cookie because we can't use get_socket_cookie()
	 * here, even on >=5.10, as we're in a kprobe. If the cookie look up fails
	 * in the inet programs, then they will look up the sk instead and move
	 * the entry to the actual cookie
	 */
	cookie = (u64)sk;

	process = execve_map_get(pid);
	if (!process)
		return 0;

	map_update_elem(&socket_cookie_to_proc_map, &cookie, process, 0);

	return 0;
}
