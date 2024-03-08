#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * For the rename operation, we hook into four points:
 *   1. kprobe/security_path_rename: Store the old/new path using the thread id.
 *      We need that for the case where the src or dst directory is not in the
 *      watched path. For the watched paths we use hash_map_inode_alloc to get
 *      the directory path based on its inode number.
 *   2. kretprobe/security_path_rename: In the case where security_path_rename
 *      fails (i.e. not enough permissions) we just cleanup vfs_rename_info_heap
 *      and return.
 *   3. kprobe/vfs_rename: We determine the details of the rename operation and
 *      check whether we are interested in either the source or destination inode.
 *   4. kretprobe/vfs_rename: If operation is succesful, we generate the path for
 *      a directory that is not watched (if needed), update our maps, and generate
 *      the rename event.
 *
 * Based on that we track only vfs_rename calls that come after security_path_rename
 * calls. There are 3 cases where this is not the case:
 *   1. in-kernel NFS server
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/nfsd/vfs.c#L1790)
 *   2. ecryptfs that seems to be a stackable filesystem and its rename operation is just
 *      to call again vfs_rename with the underlying inode/dentry.
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/ecryptfs/inode.c#L622)
 *   3. overlayfs which is a stackable filesystem. We will get the rename event for
 *      the overlayfs and then it will call vfs_rename again using the undelying
 *      inode/dentry.
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/dir.c#L1072 and
 *      https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/overlayfs.h#L210)
 */
SEC("kprobe/security_path_rename")
int BPF_KPROBE(security_path_rename, const struct path *old_dir,
	       struct dentry *old_dentry, const struct path *new_dir,
	       struct dentry *new_dentry, unsigned int flags)
{
	struct file_retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = (__u64)old_dentry,
		.flags = KRETPROBE_KEY,
	};
	struct vfs_rename_info *v;
	struct file_retprobe_key lk = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	__u64 lv = (__u64)old_dentry;
	int err, zero = 0;

	v = map_lookup_elem(&vfs_rename_info_heap, &zero);
	if (!v) {
		err = -FILE_ERR_RENAME_INFO_HEAP;
		goto security_path_rename_error;
	}

	v->old_dir = old_dir;
	v->new_dir = new_dir;
	v->need_old = v->need_new = 0;
	v->ignore_old = v->ignore_new = 0;

	if (map_update_elem(&rename_retprobe_map, &k, v, 0) < 0) {
		err = -FILE_ERR_UPDATE_RENAME_RETPROBE_MAP;
		goto security_path_rename_error;
	}

	// Create an entry for the kretprobe/security_path_rename in order to get the arguments.
	if (map_update_elem(&spr_retprobe_map, &lk, &lv, 0) < 0) {
		err = -FILE_ERR_UPDATE_SPR_RETPROBE_MAP;
		goto security_path_rename_error;
	}

	return 0;

security_path_rename_error:
	inc_error(hook_security_path_rename, -err);
	return 0;
}

SEC("kretprobe/security_path_rename")
int BPF_KRETPROBE(security_path_rename_exit, long ret)
{
	struct file_retprobe_key lk = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	__u64 *lv;
	int err;

	lv = map_lookup_elem(&spr_retprobe_map, &lk);
	if (!lv) {
		err = -FILE_ERR_LOOKUP_SPR_RETPROBE_MAP;
		goto security_path_rename_exit_error;
	}

	if (ret) {
		struct file_retprobe_key k = {
			.pid_tgid = get_current_pid_tgid(),
			.reg = *lv,
			.flags = KRETPROBE_KEY,
		};
		if (map_delete_elem(&rename_retprobe_map, &k) < 0) {
			err = -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;
			goto security_path_rename_exit_error;
		}
	}
	if (map_delete_elem(&spr_retprobe_map, &lk) < 0) {
		err = -FILE_ERR_DELETE_SPR_RETPROBE_MAP;
		goto security_path_rename_exit_error;
	}
	return 0;

security_path_rename_exit_error:
	inc_error(hook_security_path_rename, -err);
	return 0;
}
