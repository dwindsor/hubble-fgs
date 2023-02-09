#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/iterate_dir"), used)) int
BPF_KPROBE(iterate_dir, struct file *file, struct dir_context *d_ctx)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	get_ino_fs(msg, inode, dentry);

	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// find this file inside the file inode map
	// we don't care if we cannot find this in the map
	// or the action is FILTER_IGNORE
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_dir_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action_readdir;
	msg->hook = hook_iterate_dir;
	msg->ktime = ktime_get_ns();
	msg->offset = msg->size = 0;
	get_mnt_ns(&msg->mnt_ns);

	return perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));
}
