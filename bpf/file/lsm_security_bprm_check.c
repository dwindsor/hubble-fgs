#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 path_file_exec(void *ctx, struct file *file)
{
	__u32 operation, rule_id, msg_id = 0;
	struct msg_file_ops *msg;
	struct dentry *dentry;
	union exec_flags flags;
	int err;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	rule_id = run_matcher(BPF_CORE_READ(file, f_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, _(&file->f_path));

	msg->is_exe_from_memfd = is_memfd(file);
	msg->is_exe_upper_layer = is_dentry_upper(file);

	flags.d8[EXEC_ATTR_MEMFD_IDX] = msg->is_exe_from_memfd;
	flags.d8[EXEC_ATTR_UPPER_IDX] = msg->is_exe_upper_layer;

	operation = eval_selectors((struct sel_args){ action_exec, flags.d32 }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	complete_msg(msg, action_exec, hook_security_bprm_check, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	int err;

	err = path_file_exec(ctx, _(bprm->file));
	if (err < 0) {
		inc_error(hook_security_bprm_check, -err);
		return 0;
	}

	return handle_tail_call(ctx, err & FILE_OP_BLOCK ? -EPERM : 0);
}
