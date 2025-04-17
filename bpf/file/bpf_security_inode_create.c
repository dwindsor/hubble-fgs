#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all block create operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
 */
static inline __attribute__((always_inline)) __u32
block_file_create(void *ctx, struct inode *dir, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct inode_val *file_val = 0;
	int zero = 0, action = 0, err = 0;
	__u32 operation = 0, rule_id = 0, msg_id = 0;
	struct file_config_map_value *conf;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

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

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_create, 0, 0, 0, 0, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->action = action_create;
	msg->hook = hook_security_inode_create;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	if (operation & FILE_OP_BLOCK) // otherwise we will get the event after the actual create to have the inode info
		perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));
	return operation;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_create")
int BPF_PROG(security_inode_create_lsm, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	__u32 err;

	err = block_file_create(ctx, dir, dentry);
	if (err < 0) {
		inc_error(hook_security_inode_create, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_create")
int BPF_PROG(security_inode_create_fmod, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	__u32 err;

	if (ret != 0)
		return ret;

	err = block_file_create(ctx, dir, dentry);
	if (err < 0) {
		inc_error(hook_security_inode_create, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
