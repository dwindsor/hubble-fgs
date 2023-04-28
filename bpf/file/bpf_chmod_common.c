#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section(("kprobe/chmod_common")), used)) int
BPF_KPROBE(chmod_common, const struct path *path, umode_t mode)
{
	struct dentry *dentry;
	struct dentry *parent_dentry;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	__u32 operation = 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	dentry = BPF_CORE_READ(path, dentry);
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
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_file_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// At these events we don't need to update any internal maps.
	operation = eval_selectors(action_chattr);
	if (!(operation & FILE_OP_POST))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = BPF_CORE_READ(inode, i_mode);
	msg->imode[1] = mode;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->action = action_chattr;
	msg->hook = hook_chmod_common;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
