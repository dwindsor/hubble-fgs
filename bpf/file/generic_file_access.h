#ifndef __GENERIC_FILE_ACCESS__
#define __GENERIC_FILE_ACCESS__

/*
 * This function handles all read/write operations.
 * Returns: 
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int
handle_generic_file_access(void *ctx, struct file *file, int action, int hook_type)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct path path;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	__u32 operation = 0;

	if (!file)
		return -1;

	msg = get_msg_init();
	if (!msg)
		return -1;

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&file->f_inode));
	if (!inode)
		return -1;

	// get parent inode and fs info
	probe_read(&path, sizeof(path), _(&file->f_path));
	if (!path.dentry)
		return -1;

	dentry = path.dentry;
	get_ino_fs(msg, inode, dentry);

	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -1;

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
	operation = eval_selectors(action);
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

	msg->action = action;
	msg->hook = hook_type;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return (operation & FILE_OP_BLOCK) != 0;
}

#endif /* __GENERIC_FILE_ACCESS__ */
