#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__uint(value_size, 1024);
	__uint(max_entries, 1);
} rename_path_heap SEC(".maps");

FUNC_LOCAL char *get_combined_path(struct msg_file_split_path *path, __u32 *path_size)
{
	char *p, sl = '/';
	int zero = 0;

	zero = 0;
	p = map_lookup_elem(&rename_path_heap, &zero);
	if (!p)
		return 0;

	path->dir_size &= 0x1ff;
	probe_read_kernel(p, path->dir_size, path->dir);

	path->dir_size &= 0x1ff;
	probe_read_kernel(p + path->dir_size, 1, &sl);

	path->dir_size &= 0x1ff;
	path->name_size &= 0x1ff;
	probe_read_kernel(p + path->dir_size + 1, path->name_size, path->name);

	if (path_size)
		*path_size = path->dir_size + 1 + path->name_size;

	return p;
}

static inline __attribute__((always_inline)) __u32
path_rename(void *ctx, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
	struct inode *old_dir_inode, *new_dir_inode;
	__u32 s_magic, rule_id, operation = 0, src_op, dst_op, path_size = 0;
	struct msg_file_rename_ops *msg;
	struct inode *d_inode;
	umode_t i_mode;
	int zero = 0;
	char *path;

	if (!policy_filter_match())
		return 0;

	msg = map_lookup_elem(&file_rename_heap_map, &zero);
	if (!msg)
		return 0;

	init_rename_msg(msg);

	// get current inode and fs info for src (old)
	d_inode = BPF_CORE_READ(old_dentry, d_inode);
	msg->src.ino = BPF_CORE_READ(d_inode, i_ino);
	get_fs_info(&(msg->src.fs), &(msg->src.ino), d_inode, old_dentry);

	i_mode = BPF_CORE_READ(d_inode, i_mode);
	msg->flags |= get_rename_src_flags(i_mode);

	// get parent inode and fs info for src (old)
	old_dir_inode = BPF_CORE_READ(old_dir, dentry, d_inode);
	msg->src.parent_ino = BPF_CORE_READ(old_dir_inode, i_ino);
	get_fs_info(&(msg->src.parent_fs), &(msg->src.parent_ino), old_dir_inode, old_dentry);

	// get current inode and fs info for dst (new)
	d_inode = BPF_CORE_READ(new_dentry, d_inode);
	if (d_inode == 0) {
		msg->dst.ino = 0;
		msg->flags |= DST_NOT_EXISTS;
	} else {
		msg->dst.ino = BPF_CORE_READ(d_inode, i_ino);
		get_fs_info(&(msg->dst.fs), &(msg->dst.ino), d_inode, new_dentry);

		i_mode = BPF_CORE_READ(d_inode, i_mode);
		msg->flags |= get_rename_dst_flags(i_mode);
	}

	// get parent inode and fs info for dst (new)
	new_dir_inode = BPF_CORE_READ(new_dir, dentry, d_inode);
	msg->dst.parent_ino = BPF_CORE_READ(new_dir_inode, i_ino);
	get_fs_info(&(msg->dst.parent_fs), &(msg->dst.parent_ino), new_dir_inode, new_dentry);

	s_magic = BPF_CORE_READ(old_dir_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	// get source dir path
	generate_path_rename(&msg->src, (struct path *)old_dir);

	// get the dentry name for the source
	rename_copy_dname(old_dentry, &msg->src);

	path = get_combined_path(&msg->src.path, &path_size);
	src_op = eval_selectors(action_rename, msg->flags, 0, path, path_size);

	// get destination dir path
	generate_path_rename(&msg->dst, (struct path *)new_dir);

	// get the dentry name for the destination
	rename_copy_dname(new_dentry, &msg->dst);

	path = get_combined_path(&msg->dst.path, &path_size);
	dst_op = eval_selectors(action_rename, msg->flags, 0, path, path_size);

	// check both the one non-zero operation
	operation = src_op ? src_op : dst_op;
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->action = action_rename;
	msg->hook = hook_security_path_rename;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->tid = (__u32)get_current_pid_tgid();

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_rename_ops));

	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(lsm_security_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	int err;

	err = path_rename(ctx, old_dir, old_dentry, new_dir, new_dentry);
	if (err < 0) {
		inc_error(hook_security_path_rename, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
