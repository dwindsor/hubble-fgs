#include "vmlinux.h"
#include "hubble_msg.h"
#include "cookie.h"
#include "../lib/address_family.h"

#define FD_LOOKUP_SIGNAL    1024
#define S_IFMT		    00170000
#define S_IFSOCK	    0140000
#define PROTO_SHIFT_FALSE   0
#define PROTO_SHIFT_TRUE    1
#define PROTO_SHIFT_UNKNOWN 2

static inline __attribute__((always_inline)) struct sock *
fd_to_sk(struct task_struct *p, int filedesc, u16 required_protocol,
	 bool *read_ok, u16 *family, u8 discover_proto_shift, u8 *proto_shift)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fd;
	struct file *file;
	struct inode *f_inode;
	umode_t i_mode;
	struct socket *sock;
	struct sock *sk;
	long family_ret;
	u16 read_protocol;
	long proto_ret;

	if (!read_ok || !family)
		return 0;
	*read_ok = false;
	*family = 0;

	if (probe_read(&files, sizeof(files), _(&(p->files))) < 0)
		return 0;
	if (probe_read(&fdt, sizeof(fdt), _(&(files->fdt))) < 0)
		return 0;
	if (probe_read(&fd, sizeof(fd), _(&(fdt->fd))) < 0)
		return 0;
	if (probe_read(&file, sizeof(file), fd + filedesc) < 0)
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

	/* We only care about IPv4 and IPv6, but we also return the socket even if
	 * we can't read the family for some reason.
	 */
	family_ret = probe_read(family, sizeof(*family),
				_(&(sk->__sk_common.skc_family)));
	if (family_ret == 0 && (*family != AF_INET && *family != AF_INET6))
		return 0;

	/* We only return the socket for the required protocol, but we also return
	 * the socket if we can't read the protocol for some reason.
	 */
	proto_ret = probe_read(&read_protocol, sizeof(read_protocol),
			       _(&(sk->sk_protocol)));

	/* On kernels >=5.6, sk_protocol is a u16 and correctly maps to a protocol number.
	 * On kernels <5.6, sk_protocol is 8 bits of a u32 and incorrectly points at the
	 * byte before the protocol number. Therefore, to fix this, we read it as a u16 as
	 * on earlier kernels, but then shift the upper byte (second byte) to the lower
	 * (first) byte, resulting in a valid protocol number.
	 * To handle the cases where distributions have patched their kernel to the new
	 * struct layout, but have failed to update their version number, instead of
	 * relying on the kernel version number, we instead test whether we need to shift
	 * the protocol number against a known FD.
	 */
	if (!discover_proto_shift) {
		if (*proto_shift) {
			read_protocol >>= 8;
		}
		if (proto_ret == 0 && read_protocol != required_protocol) {
			return 0;
		}
	} else if (proto_shift) {
		// Check if we need to shift the protocol to match the required_protocol
		if (read_protocol == required_protocol) {
			*proto_shift = PROTO_SHIFT_FALSE;
		} else if (read_protocol >> 8 == required_protocol) {
			*proto_shift = PROTO_SHIFT_TRUE;
			read_protocol >>= 8;
		} else {
			*proto_shift = PROTO_SHIFT_UNKNOWN;
		}
	}

	if (family_ret == 0 && proto_ret == 0)
		*read_ok = true;

	return sk;
}
