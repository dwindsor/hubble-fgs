#include "bpf_file.h"
#include "vfs_mk_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 vfs_mknod(void *ctx, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int action = 0;
	__u16 md = 0;

	switch (mode & S_IFMT) {
	case 0:
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK: /* zero mode translates to S_IFREG */
		action = action_create;
		md = HASH_MAP_FILE_MODE_FILE;
		break;
	case S_IFSOCK:
		action = action_unix_socket_create;
		md = HASH_MAP_FILE_MODE_SOCKET;
		break;
	default:
		// S_IFIFO is not supported yet by FIM.
		// S_IFDIR or any other values are not allowed in mknod
		// https://elixir.bootlin.com/linux/v4.19.325/source/fs/namei.c#L3761
		return 0;
	}

	return kprobe_vfs_mk(ctx, dir, dentry, action, hook_vfs_mknod, md);
}

SEC("kprobe/vfs_mknod/63")
int BPF_KPROBE(vfs_mknod_v63, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err;

	err = vfs_mknod(ctx, dir, dentry, mode, dev);
	if (err < 0)
		inc_error(hook_vfs_mknod, -err);

	return 0;
}

SEC("kprobe/vfs_mknod/512")
int BPF_KPROBE(vfs_mknod_v512, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err;

	err = vfs_mknod(ctx, dir, dentry, mode, dev);
	if (err < 0)
		inc_error(hook_vfs_mknod, -err);

	return 0;
}

SEC("kprobe/vfs_mknod/419")
int BPF_KPROBE(vfs_mknod_v419, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err;

	err = vfs_mknod(ctx, dir, dentry, mode, dev);
	if (err < 0)
		inc_error(hook_vfs_mknod, -err);

	return 0;
}

SEC("kretprobe/vfs_mknod")
int BPF_KRETPROBE(vfs_mknod_exit, long ret)
{
	return handle_retprobe_vfs_mk(ctx, (ret == 0), hook_vfs_mknod, INODE_VAL_SRC_EBPF_MKDIR);
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_mknod")
int BPF_PROG(security_inode_mknod_lsm, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int err;

	err = security_inode_mk(ctx, dir, dentry, hook_security_inode_mknod);
	if (err < 0) {
		inc_error(hook_security_inode_mknod, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_mknod")
int BPF_PROG(security_inode_mknod_fmod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = security_inode_mk(ctx, dir, dentry, hook_security_inode_mknod);
	if (err < 0) {
		inc_error(hook_security_inode_mknod, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif