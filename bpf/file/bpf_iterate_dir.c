#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all listdir operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
 */
static inline __attribute__((always_inline)) int handle_iterate_dir(void *ctx, struct file *file)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	__u32 operation = 0;

	if (!file)
		return -FILE_ERR_FILE_ARG;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return -FILE_ERR_INODE_FROM_DENTRY;

	get_ino_fs(msg, inode, dentry);

	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	// find this file inside the file inode map
	// we don't care if we cannot find this in the map
	// or the action is FILTER_IGNORE
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->mode != HASH_MAP_FILE_MODE_DIRECTORY) // we care only for directories here
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;
	if (file_val->action == FILTER_MONITOR)
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// At these events we don't need to update any internal maps.
	operation = eval_selectors(action_readdir, 0);
	if (!(operation & FILE_OP_POST))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->action = action_readdir;
	msg->hook = hook_iterate_dir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("kprobe/iterate_dir")
int BPF_KPROBE(iterate_dir, struct file *file, struct dir_context *d_ctx)
{
	int err;

	err = handle_iterate_dir(ctx, file);
	if (err < 0)
		inc_error(hook_iterate_dir, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/file_permission")
int BPF_PROG(security_file_permission_lsm, struct file *file, int mask)
{
	int err;

	if (mask != MAY_READ)
		return 0;

	err = handle_iterate_dir(ctx, file);
	if (err < 0) {
		inc_error(hook_iterate_dir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_file_permission")
int BPF_PROG(security_file_permission_fmod, struct file *file, int mask, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	if (mask != MAY_READ)
		return 0;

	err = handle_iterate_dir(ctx, file);
	if (err < 0) {
		inc_error(hook_iterate_dir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
