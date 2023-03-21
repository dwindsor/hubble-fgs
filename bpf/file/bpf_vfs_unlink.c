#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) int
kprobe_vfs_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	unsigned int i_nlink = 0;
	bool remove_entry = false;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&dentry->d_inode));
	if (!inode)
		return 0;

	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino), _(&dir->i_ino));

	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return 0;

	get_fs_info(&(msg->parent_fs), dir, parent_dentry);

	// If inode->i_nlink == 1 (i.e. last link) we should also remove that
	// from hash_map_file_alloc.
	probe_read(&i_nlink, sizeof(i_nlink), _(&inode->i_nlink));
	remove_entry = (i_nlink == 1);

	// find this file inside the file inode map
	// if we cannot find that in map we don't have anything to remove from the map
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_file_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;

	// we don't care about that so after the map cleanup we can return
	if (file_val->action == FILTER_IGNORE)
		goto ignore_unlink;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we will update any internal maps.
	if (!check_match_binaries())
		goto ignore_unlink;
	if (!check_match_operations(action_delete))
		goto ignore_unlink;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action_delete;
	msg->hook = hook_vfs_unlink;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

ignore_unlink:
	if (remove_entry) {
		file_key.ino = msg->ino;
		file_key.dev_major = MAJOR(msg->fs.dev);
		file_key.dev_minor = MINOR(msg->fs.dev);

		map_delete_elem(&hash_map_file_alloc, &file_key);
	}

	return 0;
}

__attribute__((section(("kprobe/vfs_unlink/512")), used)) int
BPF_KPROBE(vfs_unlink_v512, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	return kprobe_vfs_unlink(ctx, dir, dentry);
}

__attribute__((section(("kprobe/vfs_unlink/419")), used)) int
BPF_KPROBE(vfs_unlink_v419, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	return kprobe_vfs_unlink(ctx, dir, dentry);
}