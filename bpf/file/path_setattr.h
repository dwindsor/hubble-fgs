#ifndef __PATH_SETATTR_H__
#define __PATH_SETATTR_H__

static inline __attribute__((always_inline)) __u32 path_setattr(void *ctx, const struct path *path, __u32 action, __u32 hook, umode_t mode, uid_t uid, gid_t gid, void (*set_attr)(struct msg_file_ops *, struct dentry *, umode_t, uid_t, gid_t))
{
	__u32 s_magic, operation, rule_id, msg_id = 0;
	struct msg_file_ops *msg;
	struct dentry *dentry;
	int err;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(path, dentry);
	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	s_magic = BPF_CORE_READ(path, dentry, d_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, (struct path *)path);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors((struct sel_args){ action, 0 }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	set_attr(msg, dentry, mode, uid, gid);

	complete_msg(msg, action, hook, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

#endif /* __PATH_SETATTR_H__ */