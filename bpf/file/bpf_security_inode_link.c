#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all link operations.
 * Returns:
 * <  0 on error
 * == 0 no need to take any further actions
 * >  0 the operation to take
 */
static inline __attribute__((always_inline)) __u32
link_create(void *ctx, struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct inode_val *file_val = 0;
	int zero = 0, action = 0, err = 0;
	__u32 operation = 0, rule_id = 0, msg_id = 0;
	struct file_config_map_value *conf;
	struct inode *old_inode;
	struct inode_key file_key;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	// get current inode and fs info
	probe_read_kernel(&old_inode, sizeof(struct inode *), _(&old_dentry->d_inode));
	if (!old_inode)
		return -FILE_ERR_INODE_FROM_DENTRY;

	get_ino_fs(msg, old_inode, old_dentry);

	// In the case we already have this inode number in our maps
	// this means that we already monitor that file. In those
	// cases we do not change its name during a link operation
	// and we keep reporting it's original name.
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, msg->ino, msg->fs.dev);
	if (file_val)
		return 0;

	// get parent inode and fs info
	probe_read_kernel(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	// find the parent directory entry
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	// we don't care for anything inside this directory
	if (file_val->action == FILTER_IGNORE)
		return 0;

	err = generate_new_file_path(dentry, msg, file_val);
	if (err < 0)
		return err;

	action = eval_patterns(msg->path.str, msg->path.size, &rule_id, conf);
	if (action < 0) // error
		return action;
	if (!action) // we didn't match
		return 0;

	// and insert that inode to the hash_map_inode_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return -FILE_ERR_GET_FILE_VAL_HEAP;

	file_val->action = action;
	file_val->size = msg->path.size;
	probe_read_str(file_val->path, MAX_FILEPATH_SIZE, msg->path.str);

	if (msg->path.flags & CONTAINER_FILE) {
		file_val->location_flags = CONTAINER_FILE;
		memcpy(file_val->container_id, msg->path.container_id, CONTAINER_ID_LEN);
	} else {
		file_val->location_flags = HOST_FILE;
	}
	file_val->mode = HASH_MAP_FILE_MODE_FILE;

	// add this new file to the map of files
	if (map_update_elem(&hash_map_inode_alloc, &file_key, file_val, 0) < 0)
		return -FILE_ERR_UPDATE_INODE_MAP;
	mod_inode_map_stats(1);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_link, 0, 0, 0, 0, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	msg->action = action_link;
	msg->hook = hook_security_inode_link;
	msg->ktime = ktime_get_ns();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

SEC("kprobe/security_inode_link")
int BPF_KPROBE(security_inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int err;

	err = link_create(ctx, old_dentry, dir, new_dentry);
	if (err < 0)
		inc_error(hook_security_inode_link, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_link")
int BPF_PROG(security_inode_link_lsm, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int err;

	err = link_create(ctx, old_dentry, dir, new_dentry);
	if (err < 0) {
		inc_error(hook_security_inode_link, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_link")
int BPF_PROG(security_inode_link_fmod, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = link_create(ctx, old_dentry, dir, new_dentry);
	if (err < 0) {
		inc_error(hook_security_inode_link, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
