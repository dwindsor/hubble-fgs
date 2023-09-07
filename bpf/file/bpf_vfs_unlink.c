#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all unlink operations.
 * Returns:
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int kprobe_vfs_unlink(void *ctx, struct inode *dir, struct dentry *dentry, __u32 hook)
{
	struct dentry *parent_dentry;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	unsigned int i_nlink = 0;
	bool remove_entry = false;
	__u32 operation = 0;

	msg = get_msg_init();
	if (!msg)
		return -1;

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&dentry->d_inode));
	if (!inode)
		return -1;

	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino), _(&dir->i_ino));

	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -1;

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
	operation = eval_selectors(action_delete, 0);
	if (!(operation & FILE_OP_POST))
		goto ignore_unlink;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->action = action_delete;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	if (operation & FILE_OP_BLOCK)
		return 1;

ignore_unlink:
	if (remove_entry) {
		file_key.ino = msg->ino;
		file_key.dev_major = MAJOR(msg->fs.dev);
		file_key.dev_minor = MINOR(msg->fs.dev);

		map_delete_elem(&hash_map_file_alloc, &file_key);
	}

	return 0;
}

SEC("kprobe/vfs_unlink/63")
int BPF_KPROBE(vfs_unlink_v63, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	kprobe_vfs_unlink(ctx, dir, dentry, hook_vfs_unlink);
	return 0;
}

SEC("kprobe/vfs_unlink/512")
int BPF_KPROBE(vfs_unlink_v512, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	kprobe_vfs_unlink(ctx, dir, dentry, hook_vfs_unlink);
	return 0;
}

SEC("kprobe/vfs_unlink/419")
int BPF_KPROBE(vfs_unlink_v419, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	kprobe_vfs_unlink(ctx, dir, dentry, hook_vfs_unlink);
	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_unlink")
int BPF_PROG(security_inode_unlink_lsm, struct inode *dir, struct dentry *dentry)
{
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (kprobe_vfs_unlink(ctx, dir, dentry, hook_security_inode_unlink) == 1)
		return -EPERM;
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_unlink")
int BPF_PROG(security_inode_unlink_fmod, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (kprobe_vfs_unlink(ctx, dir, dentry, hook_security_inode_unlink) == 1)
		return -EPERM;
	return 0;
}
#endif
