static inline __attribute__((always_inline)) int
fill_mk_retprobe_map(struct pt_regs *ctx, struct dentry *dentry, struct msg_file_ops *msg, int action, __u32 op, __u16 mode)
{
	struct vfs_mk_info *value;
	struct file_retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	int zero = 0;

	value = map_lookup_elem(&vfs_mk_info_heap, &zero);
	if (!value)
		return -FILE_ERR_MKDIR_INFO_HEAP_HEAP;

	value->dentry = dentry;
	__bpf_memcpy_builtin(&value->msg, msg, sizeof(struct msg_file_ops));
	value->action = action;
	value->operation = op;
	value->mode = mode;

	if (map_update_elem(&mk_retprobe_map, &rkey, value, 0) < 0)
		return -FILE_ERR_UPDATE_MKDIR_RETPROBE_MAP;

	/*
	 * We will use 2 keys:
	 * 1. To be used by kretprobe and indexed by pid_tgid, PT_REGS_FP_CORE, and flags == KRETPROBE_KEY
	 * 2. To be used by lsm/fmod_ret program and indexed by pid_tgid, dentry, and flags == LSM_FMOD_KEY
	 * 
	 * The reason is that we don't have access to pt_regs inside lsm/fmod_ret
	 * programs and thus we can only get the second key. On the other hand, we 
	 * also don't have access to the arguments (dentry) in the kretprobe.
	 * 
	 * In all cases, both will be deleted by the kretprobe. The kretprobe can first 
	 * delete key1 and get dentry to delete key2. kretprobe will be called even in 
	 * the case where we block the operation.
	 */
	rkey.reg = (__u64)dentry;
	rkey.flags = LSM_FMOD_KEY;
	if (map_update_elem(&mk_retprobe_map, &rkey, value, 0) < 0)
		return -FILE_ERR_UPDATE_MKDIR_RETPROBE_MAP;

	return 0;
}

static inline __attribute__((always_inline)) int
kprobe_vfs_mk(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry, __u32 ev_action, __u32 ev_hook, __u16 ev_mode)
{
	struct msg_file_ops *msg;
	struct inode *inode = dir;
	struct bpf_lpm_trie_key *key = 0;
	struct inode_val *file_val = 0;
	int action, zero = 0;
	char *buffer;
	__u32 path_size = 0, msg_id = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 operation = 0, rule_id = 0;
	struct qstr d_name;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get parent inode and fs info
	probe_read_kernel(&(msg->parent_ino), sizeof(msg->parent_ino),
			  _(&inode->i_ino));
	get_fs_info(&(msg->parent_fs), &(msg->parent_ino), inode, dentry);

	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	if (file_val->mode != HASH_MAP_FILE_MODE_DIRECTORY) // we care only for directories here
		return 0;
	if (file_val->action == FILTER_IGNORE) // we don't care for anything inside this directory
		return 0;

	// here we care about this directory and we have to create it's path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return -FILE_ERR_GET_BUFFER_HEAP;

	// first write the dentry name
	probe_read_kernel(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n"
		     : [dlen_size] "+r"(dlen_size));
	dlen_offset = 256;
	probe_read_kernel(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// now write a "/" after the dentry name
	if (ev_mode == HASH_MAP_FILE_MODE_DIRECTORY) {
		buffer[dlen_offset + dlen_size] = '/';
		path_size++;
	}

	// write the directory name
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n"
		     : [dir_size] "+r"(dir_size));
	dir_offset = 256 - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n"
		     : [dir_offset] "+r"(dir_offset));
	probe_read_kernel(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	asm volatile("%[path_size] &= 0xff;\n"
		     : [path_size] "+r"(path_size));
	probe_read_kernel(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;

	// check if we care about the new directory
	// if not just not add it in the inode map
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return -FILE_ERR_GET_TRIE_HEAP;

	key->prefixlen = msg->path.size * 8;
	__bpf_memcpy_builtin(key->data, msg->path.str, 256); // need the rest to be zero-ed

	action = filter_match(key, &rule_id);
	if (action == FILTER_NOTFOUND) // we don't care
		return 0;

	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	// create the event
	msg->action = ev_action;
	msg->hook = ev_hook;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	operation = eval_selectors((struct sel_args){ .action = ev_action, .flags = 0, .retval = 0 }, 0, (struct sel_path){ 0, 0 }, &msg_id);
	msg->msg_id = msg_id;

	// create the mk_retprobe_map value and set it for the kretprobe
	return fill_mk_retprobe_map(ctx, dentry, msg, action, operation, ev_mode);
}

static inline __attribute__((always_inline)) int
handle_retprobe_vfs_mk(struct pt_regs *ctx, bool success, __u32 hook, __u16 source)
{
	struct file_retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	struct vfs_mk_info *val;
	struct inode *d_inode;
	struct dentry *dentry;
	struct inode_key file_key;
	struct inode_val *file_val = 0;
	struct msg_file_ops *msg;
	int err, zero = 0, action = 0;
	__u32 path_size = 0;
	__u32 operation = 0;
	__u16 mode = 0;

	if (!success) {
		if ((val = map_lookup_elem(&mk_retprobe_map, &rkey))) {
			struct file_retprobe_key dkey = {
				.pid_tgid = rkey.pid_tgid,
				.reg = (__u64)val->dentry,
				.flags = LSM_FMOD_KEY,
			};
			if (map_delete_elem(&mk_retprobe_map, &dkey) < 0) {
				err = -FILE_ERR_DELETE_MKDIR_RETPROBE_MAP;
				goto vfs_mk_exit_error;
			}
		}
		if (map_delete_elem(&mk_retprobe_map, &rkey) < 0) {
			err = -FILE_ERR_DELETE_MKDIR_RETPROBE_MAP;
			goto vfs_mk_exit_error;
		}
		return 0;
	}

	msg = map_lookup_elem(&file_heap_map, &zero);
	if (!msg) {
		err = -FILE_ERR_GET_MSG_HEAP;
		goto vfs_mk_exit_error;
	}

	val = map_lookup_elem(&mk_retprobe_map, &rkey);
	if (!val) // kprobe hook decided that we don't care about that directory
		return 0;

	dentry = val->dentry;
	action = val->action;
	mode = val->mode;
	__bpf_memcpy_builtin(msg, &val->msg, sizeof(struct msg_file_ops));
	operation = val->operation;

	// we are done with 'val' so we can delete than entry
	map_delete_elem(&mk_retprobe_map, &rkey);
	rkey.reg = (__u64)dentry;
	rkey.flags = LSM_FMOD_KEY;
	map_delete_elem(&mk_retprobe_map, &rkey);

	// get current inode and fs info
	// we know that at the kretprobe hook
	probe_read_kernel(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode) {
		err = -FILE_ERR_INODE_FROM_DENTRY;
		goto vfs_mk_exit_error;
	}

	get_ino_fs(msg, d_inode, dentry);

	// and now add this to hash_map_inode_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val) {
		err = -FILE_ERR_GET_FILE_VAL_HEAP;
		goto vfs_mk_exit_error;
	}

	file_val->action = action;
	file_val->source = source;
	file_val->size = msg->path.size;
	path_size = msg->path.size;
	asm volatile("%[path_size] &= 0xff;\n"
		     : [path_size] "+r"(path_size));
	probe_read_kernel(file_val->path, path_size, msg->path.str);

	if (msg->path.flags & CONTAINER_FILE) {
		file_val->location_flags = CONTAINER_FILE;
		memcpy(file_val->container_id, msg->path.container_id, CONTAINER_ID_LEN);
	} else {
		file_val->location_flags = HOST_FILE;
	}
	file_val->mode = mode;

	if (map_update_elem(&hash_map_inode_alloc, &file_key, file_val, 0) < 0) {
		err = -FILE_ERR_UPDATE_INODE_MAP;
		goto vfs_mk_exit_error;
	}
	mod_inode_map_stats(1);

	if (action == FILTER_IGNORE) // due to path_file_exclude
		return 0;
	if (action == FILTER_MONITOR)
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid sending the message.
	// In these events have already updated any internal maps.
	if (!(operation & FILE_OP_POST))
		return operation;

	/* operation cannot be FILE_OP_BLOCK here as this operation will 
	 * be block by lsm/fmod_ret programs */
	msg->operation = FILE_OP_POST;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
				 sizeof(struct msg_file_ops));

	return 0;

vfs_mk_exit_error:
	inc_error(hook, -err);
	return 0;
}

#if defined(__FILE_ENFORCE_LSM) || defined(__FILE_ENFORCE_FMOD)
static inline __attribute__((always_inline)) int security_inode_mk(void *ctx, struct inode *dir, struct dentry *dentry, __u32 hook)
{
	struct file_retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = (__u64)dentry,
		.flags = LSM_FMOD_KEY,
	};
	struct vfs_mk_info *val;

	val = map_lookup_elem(&mk_retprobe_map, &rkey); // kprobe hook decided that we don't care about that directory
	if (!val)
		return 0;

	if (val->operation & FILE_OP_BLOCK) {
		int zero = 0;
		struct msg_file_ops *msg = map_lookup_elem(&file_heap_map, &zero);
		if (!msg)
			return -FILE_ERR_GET_MSG_HEAP;

		__bpf_memcpy_builtin(msg, &val->msg, sizeof(struct msg_file_ops));
		if (map_delete_elem(&mk_retprobe_map, &rkey) < 0)
			return -FILE_ERR_DELETE_MKDIR_RETPROBE_MAP;

		msg->hook = hook;
		msg->operation = FILE_OP_BLOCK;

		perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

		return FILE_OP_BLOCK;
	}
	return 0;
}
#endif