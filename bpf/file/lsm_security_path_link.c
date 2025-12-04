#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_file_link_ops);
	__uint(max_entries, 1);
} file_link_heap_map SEC(".maps");

static struct msg_file_link_ops *get_msg_link_init()
{
	struct msg_file_link_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_link_heap_map, &zero);
	if (!msg)
		return 0;

	memset(msg, 0, sizeof(struct msg_file_link_ops));

	msg->common.op = ISO_MSG_OP_FILE_LINK;
	msg->common.size = sizeof(struct msg_file_link_ops);
	msg->common.ktime = tg_get_ktime();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}

	return msg;
}

static void __get_path_local(struct msg_file_path *p, struct path *path)
{
	int error = 0, buflen = 0;
	char *pp;

	pp = d_path_local(path, &buflen, &error);
	if (!error) {
		asm volatile("%[buflen] &= 0xff;\n"
			     : [buflen] "+r"(buflen));
		probe_read_kernel(p->str, buflen, pp);
		p->size = buflen;
	}

	p->flags = PATH_BASED_FILE;
}

static inline __attribute__((always_inline)) __u32 path_link(void *ctx, struct dentry *old_dentry, const struct path *dir, struct dentry *new_dentry)
{
	struct msg_file_link_ops *msg;
	struct path new_path = { 0 };
	__u32 operation = 0, rule_id = 0;
	__u32 link_op = 0, target_op = 0, link_msg_id = 0, target_msg_id = 0;
	struct dentry *parent_dentry;
	struct inode *inode;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_link_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get inode numbers of the link
	msg->link.ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);
	inode = BPF_CORE_READ(new_dentry, d_inode);
	get_fs_info(&(msg->link.fs), &(msg->link.ino), inode, new_dentry);

	// get inode numbers of the parent of the link
	parent_dentry = BPF_CORE_READ(dir, dentry);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	inode = BPF_CORE_READ(parent_dentry, d_inode);
	msg->link.parent_ino = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
	get_fs_info(&(msg->link.parent_fs), &(msg->link.parent_ino), inode, parent_dentry);

	// get inode numbers of the target
	msg->target.ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
	inode = BPF_CORE_READ(old_dentry, d_inode);
	get_fs_info(&(msg->target.fs), &(msg->target.ino), inode, old_dentry);

	// get inode numbers of the parent of the target
	parent_dentry = BPF_CORE_READ(old_dentry, d_parent);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	inode = BPF_CORE_READ(parent_dentry, d_inode);
	msg->target.parent_ino = BPF_CORE_READ(parent_dentry, d_inode, i_ino);
	get_fs_info(&(msg->target.parent_fs), &(msg->target.parent_ino), inode, parent_dentry);

	// in hard links both the target and the link should exist in the same file system
	// thuse we are good if we check the magic number of the link
	rule_id = run_matcher(BPF_CORE_READ(dir, dentry, d_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path_mixed(&msg->link.path, (struct path *)dir, new_dentry);

	new_path.dentry = old_dentry;
	new_path.mnt = BPF_CORE_READ(dir, mnt);
	__get_path_local(&msg->target.path, &new_path);

	link_op = eval_selectors((struct sel_args){ .action = action_link, .flags = 0, .retval = 0 }, 0, (struct sel_path){ msg->link.path.str, msg->link.path.size }, &link_msg_id);

	target_op = eval_selectors((struct sel_args){ .action = action_link, .flags = 0, .retval = 0 }, 0, (struct sel_path){ msg->target.path.str, msg->target.path.size }, &target_msg_id);

	operation = link_op ? link_op : target_op;
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->action = action_link;
	msg->hook = hook_security_path_link;
	msg->ktime = tg_get_ktime();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = link_op ? link_msg_id : target_msg_id;
	msg->tid = (__u32)get_current_pid_tgid();

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE_LINK, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_link_ops));

	return operation;
}

SEC("lsm/path_link")
int BPF_PROG(lsm_security_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
	int err;

	err = path_link(ctx, old_dentry, new_dir, new_dentry);
	if (err < 0) {
		inc_error(hook_security_path_link, -err);
		return 0;
	}

	return handle_tail_call(ctx, handle_enforcement(err));
}
