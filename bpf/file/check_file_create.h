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
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 path_size = 0;
	int zero = 0, action = 0;
	struct inode *inode;
	struct qstr d_name;
	char *buffer;
	__u32 operation = 0, rule_id = 0;
	struct file_config_map_value *conf = 0;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get current inode and fs info
	probe_read(&inode, sizeof(struct inode *), _(&dentry->d_inode));
	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
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

	// we care about files inside this directory
	// get a buffer to generate its path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return -FILE_ERR_GET_BUFFER_HEAP;

	// first write the dentry name
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size)
		     :);
	dlen_offset = MAX_FILEPATH_SIZE;
	probe_read(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// then write the directory name
	// this is what we have in the map already (we don't traverse anything)
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n" ::[dir_size] "+r"(dir_size)
		     :);
	dir_offset = MAX_FILEPATH_SIZE - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n" ::[dir_offset] "+r"(dir_offset)
		     :);
	probe_read(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	// set the filepath inside msg
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

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
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(file_val->path, path_size, msg->path.str);

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

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_create, 0);
	if (!(operation & FILE_OP_POST))
		return 0;
	/* operation cannot be FILE_OP_BLOCK here */

	probe_read(&(msg->imode[0]), sizeof(msg->imode[0]), _(&inode->i_mode));
	probe_read(&(msg->uid[0]), sizeof(msg->uid[0]), _(&inode->i_uid));
	probe_read(&(msg->gid[0]), sizeof(msg->gid[0]), _(&inode->i_gid));

	msg->action = action_create;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = FILE_OP_POST;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return 0;
}

#endif /* __CHECK_FILE_CREATE__ */
