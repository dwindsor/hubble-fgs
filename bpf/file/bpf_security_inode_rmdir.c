#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all rmdir operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
 */
static inline __attribute__((always_inline)) int kprobe_security_inode_rmdir(void *ctx, struct inode *dir, struct dentry *dentry)
{
	struct inode *d_inode;
	struct inode_key file_key;
	struct inode_val *file_val = 0;
	struct msg_file_ops *msg;
	__u32 operation = 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	// get current inode and fs info
	probe_read_kernel(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode)
		return -FILE_ERR_INODE_FROM_DENTRY;

	get_ino_fs(msg, d_inode, dentry);

	// get parent inode and fs info
	probe_read_kernel(&(msg->parent_ino), sizeof(msg->parent_ino), _(&dir->i_ino));
	get_fs_info(&(msg->parent_fs), &(msg->parent_ino), dir, dentry);

	// check if we care about this directory
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;

	if (file_val->action == FILTER_IGNORE || file_val->action == FILTER_MONITOR)
		goto ignore_rmdir;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we will update any internal maps.
	operation = eval_selectors(action_rmdir, 0, 0, 0, 0);
	if (!(operation & FILE_OP_POST))
		goto ignore_rmdir;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->action = action_rmdir;
	msg->hook = hook_security_inode_rmdir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
				 sizeof(struct msg_file_ops));

	if (operation & FILE_OP_BLOCK)
		return operation;

ignore_rmdir:
	// delete this directory from the map with directories
	// that we are watching
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	if (map_delete_elem(&hash_map_inode_alloc, &file_key) < 0)
		return -FILE_ERR_DELETE_INODE_MAP;

	return operation;
}

SEC("kprobe/security_inode_rmdir")
int BPF_KPROBE(security_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	int err;

	err = kprobe_security_inode_rmdir(ctx, dir, dentry);
	if (err < 0)
		inc_error(hook_security_inode_rmdir, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_rmdir")
int BPF_PROG(security_inode_rmdir_lsm, struct inode *dir, struct dentry *dentry)
{
	int err;

	err = kprobe_security_inode_rmdir(ctx, dir, dentry);
	if (err < 0) {
		inc_error(hook_security_inode_rmdir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_rmdir")
int BPF_PROG(security_inode_rmdir_fmod, struct inode *dir, struct dentry *dentry, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = kprobe_security_inode_rmdir(ctx, dir, dentry);
	if (err < 0) {
		inc_error(hook_security_inode_rmdir, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
