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

#define FD_TO_SK_SUCCESS	  0
#define FD_TO_SK_INVALID_PTRS	  1
#define FD_TO_SK_WRONG_FAMILY	  2
#define FD_TO_SK_WRONG_PROTO	  3
#define FD_TO_SK_READ_ERROR_OTHER 4
#define FD_TO_SK_READ_ERROR_FILE  5
#define FD_TO_SK_READ_ERROR_INODE 6
#define FD_TO_SK_NO_SK		  7

static inline __attribute__((always_inline)) int
fd_to_sk(struct sock **sk_ret, struct task_struct *p, int filedesc, u16 required_protocol,
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

	if (!read_ok || !family || !sk_ret)
		return FD_TO_SK_INVALID_PTRS;
	*read_ok = false;
	*family = 0;

	if (probe_read(&files, sizeof(files), _(&(p->files))) < 0)
		return FD_TO_SK_READ_ERROR_OTHER;
	if (probe_read(&fdt, sizeof(fdt), _(&(files->fdt))) < 0)
		return FD_TO_SK_READ_ERROR_OTHER;
	if (probe_read(&fd, sizeof(fd), _(&(fdt->fd))) < 0)
		return FD_TO_SK_READ_ERROR_OTHER;
	if (probe_read(&file, sizeof(file), fd + filedesc) < 0)
		return FD_TO_SK_READ_ERROR_FILE;
	if (probe_read(&f_inode, sizeof(f_inode), _(&(file->f_inode))) == 0) {
		if (probe_read(&i_mode, sizeof(i_mode), _(&(f_inode->i_mode))) == 0) {
			if ((i_mode & S_IFMT) != S_IFSOCK)
				return FD_TO_SK_READ_ERROR_INODE;
		}
	}

	/* In a socket, the private_data in the struct file *is* the struct sock.
	 * See sock_from_file() in net/socket.c for confirmation.
	 */
	if (probe_read(&sock, sizeof(sock), _(&(file->private_data))) < 0)
		return FD_TO_SK_READ_ERROR_FILE;

	if (probe_read(&sk, sizeof(sk), _(&(sock->sk))) < 0)
		return FD_TO_SK_NO_SK;

	/* We only care about IPv4 and IPv6, but we also return the socket even if
	 * we can't read the family for some reason.
	 */
	family_ret = probe_read(family, sizeof(*family),
				_(&(sk->__sk_common.skc_family)));
	if (family_ret == 0 && (*family != AF_INET && *family != AF_INET6))
		return FD_TO_SK_WRONG_FAMILY;

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
	 * 
	 * As a consequence of the BTF correctly identifying the location of an 8 bit
	 * protocol field, we would actually have a set of flags occupying our upper 8
	 * bits, causing direct comparisons to known protocol numbers to fail. As we do
	 * not intend to support protocol numbers > 255 currently, we shall simply mask
	 * off these upper 8 bits to prevent these from upsetting our comparison.
	 */
	if (!discover_proto_shift) {
		if (*proto_shift) {
			read_protocol >>= 8;
		} else {
			read_protocol &= 0xff;
		}
		if (proto_ret == 0 && read_protocol != required_protocol) {
			return FD_TO_SK_WRONG_PROTO;
		}
	} else if (proto_shift) {
		// Check if we need to shift the protocol to match the required_protocol
		if ((read_protocol & 0xff) == required_protocol) {
			*proto_shift = PROTO_SHIFT_FALSE;
		} else if (read_protocol >> 8 == required_protocol) {
			*proto_shift = PROTO_SHIFT_TRUE;
		} else {
			*proto_shift = PROTO_SHIFT_UNKNOWN;
		}
	}

	if (family_ret == 0 && proto_ret == 0)
		*read_ok = true;

	*sk_ret = sk;
	return FD_TO_SK_SUCCESS;
}
