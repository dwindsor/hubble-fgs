#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 unix_stream_connect(void *ctx, struct sock *sock, struct sock *other, struct sock *newsk)
{
	__u32 operation, rule_id, msg_id = 0;
	int err;
	struct msg_file_ops *msg;
	struct unix_sock *unix_sock = (struct unix_sock *)other;
	struct dentry *dentry = BPF_CORE_READ(unix_sock, path.dentry);

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	rule_id = run_matcher(BPF_CORE_READ(dentry, d_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, _(&unix_sock->path));

	operation = eval_selectors((struct sel_args){ action_unix_socket_connect, 0 }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	complete_msg(msg, action_unix_socket_connect, hook_security_unix_stream_connect, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(lsm_security_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
	int err;

	err = unix_stream_connect(ctx, sock, other, newsk);
	if (err < 0) {
		inc_error(hook_security_unix_stream_connect, -err);
		return 0;
	}

	return handle_enforcement(err);
}