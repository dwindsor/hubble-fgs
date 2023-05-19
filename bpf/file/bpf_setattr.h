#ifndef __BPF_SETATTR__
#define __BPF_SETATTR__

static inline __attribute__((always_inline)) struct msg_file_ops *generic_chattr(struct dentry *dentry, __u32 action)
{
	struct inode *inode;
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	__u32 operation = 0;

	msg = get_msg_init();
	if (!msg)
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
	operation = eval_selectors(action);
	if (!(operation & FILE_OP_POST))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->action = action;

	return msg;
}

static inline __attribute__((always_inline)) int
kprobe_do_truncate(void *ctx, struct dentry *dentry, loff_t len, __u32 hook)
{
	struct msg_file_ops *msg;

	msg = generic_chattr(dentry, action_write);
	if (!msg)
		return -1;

	msg->hook = hook;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return (msg->operation & FILE_OP_BLOCK) != 0;
}

static inline __attribute__((always_inline)) int
kprobe_chmod_common(void *ctx, struct dentry *dentry, umode_t mode, __u32 hook)
{
	struct msg_file_ops *msg;
	struct inode *inode;

	msg = generic_chattr(dentry, action_chattr);
	if (!msg)
		return -1;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return -1;

	msg->imode[0] = BPF_CORE_READ(inode, i_mode);
	msg->imode[1] = mode;

	msg->hook = hook;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return (msg->operation & FILE_OP_BLOCK) != 0;
}

static inline __attribute__((always_inline)) int
kprobe_chown_common(void *ctx, struct dentry *dentry, uid_t curr_user, uid_t new_user, gid_t curr_group, gid_t new_group, __u32 hook)
{
	struct msg_file_ops *msg;

	msg = generic_chattr(dentry, action_chattr);
	if (!msg)
		return -1;

	msg->uid[0] = curr_user;
	msg->uid[1] = new_user;
	msg->gid[0] = curr_group;
	msg->gid[1] = new_group;

	msg->hook = hook;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return (msg->operation & FILE_OP_BLOCK) != 0;
}

#endif /* __BPF_SETATTR__ */
