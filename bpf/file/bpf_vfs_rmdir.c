#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) int
kprobe_vfs_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
	struct inode *d_inode;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct msg_file_ops *msg;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode)
		return 0;

	get_ino_fs(msg, d_inode, dentry);

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino), _(&dir->i_ino));
	get_fs_info(&(msg->parent_fs), dir, dentry);

	// check if we care about this directory
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_dir_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;

	if (file_val->action == FILTER_IGNORE)
		goto ignore_rmdir;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we will update any internal maps.
	if (!check_match_binaries())
		goto ignore_rmdir;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	msg->action = action_rmdir;
	msg->hook = hook_vfs_rmdir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

ignore_rmdir:
	// delete this directory from the map with directories
	// that we are watching
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	map_delete_elem(&hash_map_dir_alloc, &file_key);

	return 0;
}

__attribute__((section(("kprobe/vfs_rmdir/512")), used)) int
BPF_KPROBE(vfs_rmdir_v512, struct user_namespace *mnt_userns, struct inode *dir,
	   struct dentry *dentry)
{
	return kprobe_vfs_rmdir(ctx, dir, dentry);
}

__attribute__((section(("kprobe/vfs_rmdir/419")), used)) int
BPF_KPROBE(vfs_rmdir_v419, struct inode *dir, struct dentry *dentry)
{
	return kprobe_vfs_rmdir(ctx, dir, dentry);
}