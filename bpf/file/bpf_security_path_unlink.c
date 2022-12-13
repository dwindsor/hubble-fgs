#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section(("kprobe/security_path_unlink")), used)) int
BPF_KPROBE(security_path_unlink, const struct path *dir, struct dentry *dentry)
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
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dir->dentry));
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

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

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action_delete;
	msg->hook = hook_security_path_unlink;
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
