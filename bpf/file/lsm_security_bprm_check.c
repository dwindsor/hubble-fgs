#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"
#include "bpf_secureexec.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

FUNC_LOCAL __u32 path_file_exec(void *ctx, struct linux_binprm *bprm)
{
	struct msg_file_ops *msg;
	struct dentry *dentry;
	union exec_flags flags;
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};
	__u32 operation, rule_id, msg_id = 0, err;
	char header[2] = { 0, 0 };

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	rule_id = run_matcher(BPF_CORE_READ(bprm, file, f_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, _(&bprm->file->f_path));

	msg->is_exe_from_memfd = is_memfd(BPF_CORE_READ(bprm, file));
	msg->is_exe_upper_layer = is_dentry_upper(BPF_CORE_READ(bprm, file));

	flags.d8[EXEC_ATTR_MEMFD_IDX] = msg->is_exe_from_memfd;
	flags.d8[EXEC_ATTR_UPPER_IDX] = msg->is_exe_upper_layer;

	operation = eval_selectors((struct sel_args){ .action = action_exec, .flags = flags.d32, .retval = 0, .secureexec = INVALID_SECUREEXEC }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	complete_msg(msg, action_exec, hook_security_bprm_check, operation, rule_id, 0, msg_id);

	// If we need to block *or* this is a script we need to send a message
	// because the next hook (i.e. bprm_creds_from_file) will not be executed.
	// Check if this a script in a simimilar way to what kernel does
	// https://elixir.bootlin.com/linux/v6.19.8/source/fs/binfmt_script.c#L40
	probe_read_kernel(header, 2 * sizeof(char), _(&bprm->buf[0]));
	if ((operation & FILE_OP_BLOCK) || ((header[0] == '#') && (header[1] == '!')))
		perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));
	else
		map_update_elem(&exec_cred_map, &key, msg, 0);

	return operation;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	int err;

	err = path_file_exec(ctx, bprm);
	if (err < 0) {
		inc_error(hook_security_bprm_check, -err);
		return 0;
	}

	return handle_tail_call(ctx, handle_enforcement(err));
}
