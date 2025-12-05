#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#define __FILE_DIGEST_LSM
#include "bpf_file.h"
#include "bpf_secureexec.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm.s/bprm_check_security")
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};
	__u32 operation, rule_id, msg_id = 0;
	struct digest_key *digest = 0;
	struct msg_file_ops *msg;
	union exec_flags flags;
	struct dentry *dentry;
	struct file *file;
	int err;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg) {
		err = -FILE_ERR_GET_MSG_HEAP;
		goto lsm_bprm_check_security_error;
	}

	file = _(bprm->file);
	if (!file) {
		err = -FILE_ERR_FILE_FROM_BPRM;
		goto lsm_bprm_check_security_error;
	}

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry) {
		err = -FILE_ERR_DENTRY_FROM_FILE;
		goto lsm_bprm_check_security_error;
	}

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		goto lsm_bprm_check_security_error;

	rule_id = run_matcher(BPF_CORE_READ(file, f_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, _(&file->f_path));

	msg->digest.ok = 1;
	msg->digest.algo = ima_file_hash(_(bprm->file), msg->digest.digest, IMA_MAX_DIGEST_SIZE);
	digest = &msg->digest;

	msg->is_exe_from_memfd = is_memfd(file);
	msg->is_exe_upper_layer = is_dentry_upper(file);

	flags.d8[EXEC_ATTR_MEMFD_IDX] = msg->is_exe_from_memfd;
	flags.d8[EXEC_ATTR_UPPER_IDX] = msg->is_exe_upper_layer;

	operation = eval_selectors((struct sel_args){ .action = action_exec, .flags = flags.d32, .retval = 0, .secureexec = INVALID_SECUREEXEC }, digest, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST)) {
		err = operation;
		goto lsm_bprm_check_security_ret;
	}

	complete_msg(msg, action_exec, hook_security_bprm_check, operation, rule_id, 0, msg_id);

	// Getting a file digest requires a sleepable LSM program.
	// Sleepable programs can only use array, hash, ringbuf and local storage maps.
	// To overcome this limitation we use an fexit program to call perf_event_output
	// and send the event to the user-space. Fexit program always runs after
	// the lsm.s program and they communicate through the exec_retprobe_map map.
	err = map_update_elem(&exec_retprobe_map, &key, msg, 0);
	if (err != 0) {
		err = -FILE_ERR_UPDATE_EXEC_RETPROBE_MAP;
		goto lsm_bprm_check_security_error;
	}

lsm_bprm_check_security_ret:
	return handle_enforcement(err);

lsm_bprm_check_security_error:
	inc_error(hook_security_bprm_check, -err);
	return 0;
}

SEC("fexit/security_bprm_check")
int BPF_PROG(security_bprm_check_fexit, struct linux_binprm *bprm)
{
	struct msg_file_ops *msg;
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};

	msg = map_lookup_elem(&exec_retprobe_map, &key);
	if (!msg)
		return 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	// after sending the message we can delete the map entry
	map_delete_elem(&exec_retprobe_map, &key);

	return 0;
}
