#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 path_mknod(void *ctx, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	__u32 operation = 0, rule_id, msg_id = 0;
	__u64 uid_gid = get_current_uid_gid();
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get parent inode and fs info
	parent_dentry = BPF_CORE_READ(dir, dentry);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	rule_id = run_matcher(BPF_CORE_READ(dir, dentry, d_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path_mixed(&msg->path, (struct path *)dir, dentry);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	operation = eval_selectors((struct sel_args){ .action = action_create, .flags = 0, .retval = 0 }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->imode[0] = mode;
	msg->uid[0] = uid_gid & 0xFFFFFFFFUL;
	msg->gid[0] = uid_gid >> 32;

	complete_msg(msg, action_create, hook_security_path_mknod, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("lsm/path_mknod")
int BPF_PROG(security_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
	int err;

	err = path_mknod(ctx, dir, dentry, mode);
	if (err < 0) {
		inc_error(hook_security_path_mknod, -err);
		return 0;
	}

	return handle_enforcement(err);
}
