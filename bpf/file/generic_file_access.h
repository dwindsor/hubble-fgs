#ifndef __GENERIC_FILE_ACCESS__
#define __GENERIC_FILE_ACCESS__

/*
 * This function handles all read/write operations.
 * Returns: 
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
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
	struct io_uring_op_key key = {
		.file_ptr = (__u64)file,
		.pid_tgid = get_current_pid_tgid(),
	};
	struct io_uring_op_val *val;

	if (!file)
		return -FILE_ERR_FILE_ARG;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	val = map_lookup_elem(&io_uring_map, &key);
	if (val) { // we are in the middle of io_uring operation
		struct execve_map_value *enter = event_find_curr_task(val->user_task);
		if (enter) {
			msg->current.pid = enter->key.pid;
			msg->current.ktime = enter->key.ktime;
		}
	}

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&file->f_inode));
	if (!inode)
		return -FILE_ERR_INODE_FROM_FILE;

	// get parent inode and fs info
	probe_read(&path, sizeof(path), _(&file->f_path));
	if (!path.dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	dentry = path.dentry;
	get_ino_fs(msg, inode, dentry);

	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

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
	operation = eval_selectors(action, 0);
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
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
				 sizeof(struct msg_file_ops));

	return operation;
}

#endif /* __GENERIC_FILE_ACCESS__ */
