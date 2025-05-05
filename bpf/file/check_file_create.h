#ifndef __CHECK_FILE_CREATE__
#define __CHECK_FILE_CREATE__

/*
 * This function handles all create operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 */
static inline __attribute__((always_inline)) __u32 check_file_create(void *ctx, struct file *f, struct dentry *dentry, __u32 hook)
{
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct inode_key file_key;
	struct inode_val *file_val = 0;
	int zero = 0, action = 0, err = 0;
	struct inode *inode;
	__u32 operation = 0, rule_id = 0, msg_id = 0;
	struct file_config_map_value *conf = 0;

	if (!policy_filter_match())
		return 0;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get current inode and fs info
	probe_read_kernel(&inode, sizeof(struct inode *), _(&dentry->d_inode));
	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read_kernel(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	// find the parent directory entry
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	// we don't care for anything inside this directory
	if (file_val->action == FILTER_IGNORE)
		return 0;

	err = generate_new_file_path(dentry, msg, file_val);
	if (err < 0)
		return err;

	action = eval_patterns(msg->path.str, msg->path.size, &rule_id, conf);
	if (action < 0) // error
		return action;
	if (!action) // we didn't match
		return 0;

	// and insert that inode to the hash_map_inode_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return -FILE_ERR_GET_FILE_VAL_HEAP;

	file_val->action = action;
	file_val->size = msg->path.size;
	probe_read_str(file_val->path, MAX_FILEPATH_SIZE, msg->path.str);

	if (msg->path.flags & CONTAINER_FILE) {
		file_val->location_flags = CONTAINER_FILE;
		memcpy(file_val->container_id, msg->path.container_id, CONTAINER_ID_LEN);
	} else {
		file_val->location_flags = HOST_FILE;
	}
	file_val->mode = HASH_MAP_FILE_MODE_FILE;

	// add this new file to the map of files
	if (map_update_elem(&hash_map_inode_alloc, &file_key, file_val, 0) < 0)
		return -FILE_ERR_UPDATE_INODE_MAP;
	mod_inode_map_stats(1);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors((struct sel_args){ action_create, 0 }, 0, (struct sel_path){ 0, 0 }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;
	/* operation cannot be FILE_OP_BLOCK here */

	probe_read_kernel(&(msg->imode[0]), sizeof(msg->imode[0]), _(&inode->i_mode));
	probe_read_kernel(&(msg->uid[0]), sizeof(msg->uid[0]), _(&inode->i_uid));
	probe_read_kernel(&(msg->gid[0]), sizeof(msg->gid[0]), _(&inode->i_gid));

	msg->action = action_create;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = FILE_OP_POST;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return 0;
}

#endif /* __CHECK_FILE_CREATE__ */
