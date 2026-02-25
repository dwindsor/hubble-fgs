#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define DELETED_STR " (deleted)"
#define DELETED_LEN 10

/*
 * This function handles temporary file operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
 */
static inline __attribute__((always_inline)) __u32
file_open(void *ctx, struct file *file)
{
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct inode_val *file_val = 0;
	int zero = 0, action = 0, err = 0;
	__u32 operation = 0, rule_id = 0, msg_id = 0;
	struct file_config_map_value *conf;
	struct inode *inode;
	struct dentry *dentry;
	__u32 open_flags;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	// get current inode and fs info
	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return -FILE_ERR_INODE_FROM_DENTRY;

	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read_kernel(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	open_flags = BPF_CORE_READ(file, f_flags);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors((struct sel_args){ .action = action_open, .flags = open_flags, .retval = 0 }, 0, (struct sel_path){ 0, 0 }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	// first check if we care about the file/dir itself
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, msg->ino, msg->fs.dev);
	// we cannot find that so let's check the directory
	if (!file_val)
		goto check_dir;
	if (file_val->mode != HASH_MAP_FILE_MODE_FILE && file_val->mode != HASH_MAP_FILE_MODE_DIRECTORY) // we care only for files and directories here
		return 0;
	if (file_val->action == FILTER_IGNORE || file_val->action == FILTER_MONITOR) // we don't care for anything inside this directory
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	goto generate_message;

check_dir:
	// find the parent directory entry
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	if (file_val->mode != HASH_MAP_FILE_MODE_DIRECTORY) // we care only for directories here
		return 0;
	if (file_val->action == FILTER_IGNORE) // we don't care for anything inside this directory
		return 0;

	err = generate_new_file_path(dentry, msg, file_val);
	if (err < 0)
		return err;

#ifdef __LARGE_BPF_PROG
	// append (deleted) at the file name in a similar way to d_path
	if (d_unlinked(dentry) && msg->path.size < (MAX_FILEPATH_SIZE - DELETED_LEN)) {
		// this is to satisfy the verifier, previous check is msg->path.size <
		// 256 - 10 = 246 so that should be safe to AND msg->path.size with 255.
		asm volatile("%[size] &= 0xff;\n"
			     : [size] "+r"(msg->path.size));
		probe_read_kernel(msg->path.str + msg->path.size, DELETED_LEN, DELETED_STR);
		msg->path.size += DELETED_LEN;
	}
#endif

	action = eval_patterns(msg->path.str, msg->path.size, &rule_id, conf);
	if (action < 0) // error
		return action;
	if (action != FILTER_MATCH)
		return 0; // nothing to do

generate_message:
	msg->action = action_open;
	msg->hook = hook_security_file_open;
	msg->ktime = tg_get_ktime();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;
	msg->open_flags = open_flags;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open, struct file *file)
{
	int err;

	err = file_open(ctx, file);
	if (err < 0)
		inc_error(hook_security_file_open, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/file_open")
int BPF_PROG(security_file_open_lsm, struct file *file)
{
	int err;

	err = file_open(ctx, file);
	if (err < 0) {
		inc_error(hook_security_file_open, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_file_open")
int BPF_PROG(security_file_open_fmod, struct file *file, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = file_open(ctx, file);
	if (err < 0) {
		inc_error(hook_security_file_open, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif
