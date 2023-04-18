#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section(("kprobe/chown_common")), used)) int
BPF_KPROBE(chown_common, const struct path *path, uid_t user, gid_t group)
{
	struct dentry *dentry;
	struct dentry *parent_dentry;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;

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
	if (!check_match_binaries())
		return 0;
	if (!check_match_operations(action_chattr))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = BPF_CORE_READ(inode, i_uid).val;
	msg->uid[1] = user;
	msg->gid[0] = BPF_CORE_READ(inode, i_gid).val;
	msg->gid[1] = group;

	msg->action = action_chattr;
	msg->hook = hook_chown_common;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
