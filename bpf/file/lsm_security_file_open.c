#define __V61_BPF_PROG
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 path_file_open(void *ctx, struct file *file)
{
	__u32 operation = 0, rule_id, open_flags, s_magic;
	struct msg_file_ops *msg;
	struct dentry *dentry;
	int err;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	s_magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	open_flags = BPF_CORE_READ(file, f_flags);
	operation = eval_selectors(action_open, open_flags, 0);
	if (!(operation & FILE_OP_POST))
		return 0;

	generate_path(msg, _(&file->f_path));

	complete_msg(msg, action_open, hook_security_file_open, operation, rule_id, open_flags);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	int err;

	err = path_file_open(ctx, file);
	if (err < 0) {
		inc_error(hook_security_file_open, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}