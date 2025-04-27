#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_file_symlink_ops);
	__uint(max_entries, 1);
} file_symlink_heap_map SEC(".maps");

static struct msg_file_symlink_ops *get_msg_symlink_init()
{
	struct msg_file_symlink_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_symlink_heap_map, &zero);
	if (!msg)
		return 0;

	memset(msg, 0, sizeof(struct msg_file_symlink_ops));

	msg->common.op = ISO_MSG_OP_FILE_SYMLINK;
	msg->common.size = sizeof(struct msg_file_symlink_ops);
	msg->common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}

	return msg;
}

static inline __attribute__((always_inline)) __u32 path_symlink(void *ctx, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	__u32 operation = 0, rule_id = 0, s_magic = 0;
	__u32 link_op = 0, target_op = 0, link_msg_id = 0, target_msg_id = 0;
	struct msg_file_symlink_ops *msg;
	struct dentry *parent_dentry;
	struct inode *inode;
	long ret;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_symlink_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get inode numbers of the link
	msg->link.ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	inode = BPF_CORE_READ(dentry, d_inode);
	get_fs_info(&(msg->link.fs), &(msg->link.ino), inode, dentry);

	// get inode numbers of the parent of the link
	parent_dentry = BPF_CORE_READ(dir, dentry);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	inode = BPF_CORE_READ(parent_dentry, d_inode);
	msg->link.parent_ino = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
	get_fs_info(&(msg->link.parent_fs), &(msg->link.parent_ino), inode, parent_dentry);

	// in symbolic links we check only the link for the file system check
	// as we don't know where the target resides
	s_magic = BPF_CORE_READ(dir, dentry, d_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path_mixed(&msg->link.path, (struct path *)dir, dentry);
	ret = probe_read_kernel_str(msg->target.str, MAX_FILEPATH_SIZE, old_name);
	if (ret > 0) // on success
		msg->target.size = ret - 1; // as this includes the trailing NUL character

	link_op = eval_selectors(action_symlink, 0, 0, msg->link.path.str, msg->link.path.size, &link_msg_id);

	target_op = eval_selectors(action_symlink, 0, 0, msg->target.str, msg->target.size, &target_msg_id);

	operation = link_op ? link_op : target_op;
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->action = action_symlink;
	msg->hook = hook_security_path_symlink;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = link_op ? link_msg_id : target_msg_id;
	msg->tid = (__u32)get_current_pid_tgid();

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE_SYMLINK, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_symlink_ops));

	return operation;
}

SEC("lsm/path_symlink")
int BPF_PROG(lsm_security_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	int err = 0;

	err = path_symlink(ctx, dir, dentry, old_name);
	if (err < 0) {
		inc_error(hook_security_path_symlink, -err);
		return 0;
	}

	return handle_tail_call(ctx, err & FILE_OP_BLOCK ? -EPERM : 0);
}