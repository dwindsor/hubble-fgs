#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"
#include "bpf_secureexec.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(security_bprm_committing_creds_lsm, struct linux_binprm *bprm, struct file *file, int ret)
{
	struct msg_file_ops *msg;
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};
	__u32 operation, rule_id, msg_id = 0;
	union exec_flags flags;
	struct digest_key *digest = 0;

	if (ret)
		return ret;

	msg = map_lookup_elem(&exec_cred_map, &key);
	if (!msg)
		return 0;

	rule_id = msg->rule_id;

	generate_secureexec(msg, bprm);

	flags.d8[EXEC_ATTR_MEMFD_IDX] = msg->is_exe_from_memfd;
	flags.d8[EXEC_ATTR_UPPER_IDX] = msg->is_exe_upper_layer;

	if (msg->digest.ok)
		digest = &msg->digest;

	operation = eval_selectors((struct sel_args){ .action = action_exec, .flags = flags.d32, .retval = 0, .secureexec = msg->secureexec, .uid = msg->uid[NEWVAL], .gid = msg->gid[NEWVAL] }, digest, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		goto out;

	complete_msg(msg, action_exec, hook_security_bprm_creds_from_file, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

out:
	map_delete_elem(&exec_cred_map, &key);

	// if FILE_OP_BLOCK is not defined in operation it just returns 0
	return handle_enforcement(operation);
}
