#include "bpf_file.h"
#include "vfs_mk_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/vfs_mkdir/63")
int BPF_KPROBE(vfs_mkdir_v63, struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *dentry, umode_t mode)
{
	int err;

	err = kprobe_vfs_mk(ctx, dir, dentry, action_mkdir, hook_vfs_mkdir, HASH_MAP_FILE_MODE_DIRECTORY);
	if (err < 0)
		inc_error(hook_vfs_mkdir, -err);

	return 0;
}

SEC("kprobe/vfs_mkdir/512")
int BPF_KPROBE(vfs_mkdir_v512, struct user_namespace *mnt_userns, struct inode *dir,
	       struct dentry *dentry, umode_t mode)
{
	int err;

	err = kprobe_vfs_mk(ctx, dir, dentry, action_mkdir, hook_vfs_mkdir, HASH_MAP_FILE_MODE_DIRECTORY);
	if (err < 0)
		inc_error(hook_vfs_mkdir, -err);

	return 0;
}

SEC("kprobe/vfs_mkdir/419")
int BPF_KPROBE(vfs_mkdir_v419, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;

	err = kprobe_vfs_mk(ctx, dir, dentry, action_mkdir, hook_vfs_mkdir, HASH_MAP_FILE_MODE_DIRECTORY);
	if (err < 0)
		inc_error(hook_vfs_mkdir, -err);

	return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(vfs_mkdir_exit, long ret)
{
	return handle_retprobe_vfs_mk(ctx, (ret == 0), hook_vfs_mkdir, INODE_VAL_SRC_EBPF_MKDIR);
}

SEC("kretprobe/vfs_mkdir/614")
int BPF_KRETPROBE(vfs_mkdir_exit_v614, struct dentry *dentry)
{
	return handle_retprobe_vfs_mk(ctx, (dentry != 0), hook_vfs_mkdir, INODE_VAL_SRC_EBPF_MKDIR);
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_mkdir")
int BPF_PROG(security_inode_mkdir_lsm, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;

	err = security_inode_mk(ctx, dir, dentry, hook_security_inode_mkdir);
	if (err < 0) {
		inc_error(hook_security_inode_mkdir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_mkdir")
int BPF_PROG(security_inode_mkdir_fmod, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = security_inode_mk(ctx, dir, dentry, hook_security_inode_mkdir);
	if (err < 0) {
		inc_error(hook_security_inode_mkdir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
