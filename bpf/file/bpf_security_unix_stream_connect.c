#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 unix_stream_connect(void *ctx, struct sock *sock, struct sock *other, struct sock *newsk)
{
	struct msg_file_ops *msg;
	struct unix_sock *unix_sock = (struct unix_sock *)other;
	struct dentry *dentry = BPF_CORE_READ(unix_sock, path.dentry);
	struct inode_val *file_val = 0;
	__u32 operation = 0, msg_id = 0;
	int err;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	// find this file inside the file inode map
	// if we cannot find that in map we don't have anything to remove from the map
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->mode != HASH_MAP_FILE_MODE_SOCKET) // we care only for unix sockets here
		return 0;
	if (file_val->action == FILTER_IGNORE || file_val->action == FILTER_MONITOR) // we don't care about that
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	operation = eval_selectors((struct sel_args){ .action = action_unix_socket_connect, .flags = 0, .retval = 0 }, 0, (struct sel_path){ 0, 0 }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->action = action_unix_socket_connect;
	msg->hook = hook_security_unix_stream_connect;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
				 sizeof(struct msg_file_ops));

	return operation;
}

SEC("kprobe/security_unix_stream_connect")
int BPF_KPROBE(security_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
	int err;

	err = unix_stream_connect(ctx, sock, other, newsk);
	if (err < 0)
		inc_error(hook_security_unix_stream_connect, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/unix_stream_connect")
int BPF_PROG(security_unix_stream_connect_lsm, struct sock *sock, struct sock *other, struct sock *newsk, int ret)
{
	int err;

	if (ret)
		return ret;

	err = unix_stream_connect(ctx, sock, other, newsk);
	if (err < 0) {
		inc_error(hook_security_unix_stream_connect, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_unix_stream_connect")
int BPF_PROG(security_unix_stream_connect_fmod, struct sock *sock, struct sock *other, struct sock *newsk, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = unix_stream_connect(ctx, sock, other, newsk);
	if (err < 0) {
		inc_error(hook_security_unix_stream_connect, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif
