#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * For the rename operation, we hook into four points:
 *   1. kprobe/security_path_rename: Store the old/new path using the thread id.
 *      We need that for the case where the src or dst directory is not in the
 *      watched path. For the watched paths we use hash_map_dir_alloc to get
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
	struct retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = 0,
		.flags = KRETPROBE_KEY,
	};
	struct vfs_rename_info *v;
	int zero = 0;

	v = map_lookup_elem(&vfs_rename_info_heap, &zero);
	if (!v)
		return 0;

	v->old_dir = old_dir;
	v->new_dir = new_dir;
	v->need_old = 0;
	v->need_new = 0;

	map_update_elem(&rename_retprobe_map, &k, v, 0);
	return 0;
}

SEC("kretprobe/security_path_rename")
int BPF_KRETPROBE(security_path_rename_exit, long ret)
{
	if (ret) {
		struct retprobe_key k = {
			.pid_tgid = get_current_pid_tgid(),
			.reg = 0,
			.flags = KRETPROBE_KEY,
		};
		map_delete_elem(&rename_retprobe_map, &k);
	}
	return 0;
}
