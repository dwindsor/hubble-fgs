#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 path_rmdir(void *ctx, const struct path *dir, struct dentry *new_dentry)
{
	struct dentry *parent_dentry;
	__u32 s_magic, operation, rule_id;
	struct msg_file_ops *msg;
	struct inode *inode;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get current inode and fs info
	inode = BPF_CORE_READ(new_dentry, d_inode);
	if (!inode)
		return -FILE_ERR_INODE_FROM_DENTRY;

	get_ino_fs(msg, inode, new_dentry);

	// get parent inode and fs info
	parent_dentry = BPF_CORE_READ(dir, dentry);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	s_magic = BPF_CORE_READ(new_dentry, d_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path_mixed(msg, (struct path *)dir, new_dentry);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_rmdir, 0, 0, msg->path.str, msg->path.size);
	if (!(operation & FILE_OP_POST))
		return operation;

	complete_msg(msg, action_rmdir, hook_security_path_rmdir, operation, rule_id, 0);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("lsm/path_rmdir")
int BPF_PROG(lsm_security_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	int err;

	err = path_rmdir(ctx, dir, dentry);
	if (err < 0) {
		inc_error(hook_security_path_rmdir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
