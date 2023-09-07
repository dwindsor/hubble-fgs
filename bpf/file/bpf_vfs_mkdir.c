#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) void
fill_mkdir_retprobe_map(struct pt_regs *ctx, struct dentry *dentry, struct msg_file_ops *msg, int action, __u32 op)
{
	struct vfs_mkdir_info *value;
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	int zero = 0;

	value = map_lookup_elem(&vfs_mkdir_info_heap, &zero);
	if (!value)
		return;

	value->dentry = dentry;
	memcpy(&value->msg, msg, sizeof(struct msg_file_ops));
	value->action = action;
	value->operation = op;

	map_update_elem(&mkdir_retprobe_map, &rkey, value, 0);
	/*
	 * We will use 2 keys:
	 * 1. To be used by kretprobe and indexed by pid_tgid, PT_REGS_FP_CORE, and flags == KRETPROBE_KEY
	 * 2. To be used by lsm/fmod_ret program and indexed by pid_tgid, dentry, and flags == LSM_FMOD_KEY
	 * 
	 * The reason is that we don't have access to pt_regs inside lsm/fmod_ret
	 * programs and thus we can only get the second key. On the other hand, we 
	 * also don't have access to the arguments (dentry) in the kretprobe.
	 * 
	 * In all cases, both will be deleted by the kretprobe. The kretprobe can first 
	 * delete key1 and get dentry to delete key2. kretprobe will be called even in 
	 * the case where we block the operation.
	 */
	rkey.reg = (__u64)dentry;
	rkey.flags = LSM_FMOD_KEY;
	map_update_elem(&mkdir_retprobe_map, &rkey, value, 0);
}

static inline __attribute__((always_inline)) int
kprobe_vfs_mkdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry,
		 umode_t mode)
{
	struct msg_file_ops *msg;
	struct inode *inode = dir;
	struct bpf_lpm_trie_key *key = 0;
	struct hash_map_file_val *file_val = 0;
	int action, zero = 0;
	char *buffer;
	__u32 path_size = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 operation = 0, rule_id = 0;
	struct qstr d_name;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino),
		   _(&inode->i_ino));
	get_fs_info(&(msg->parent_fs), inode, dentry);

	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_dir_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	// we don't care for anything inside this directory
	if (file_val->action == FILTER_IGNORE)
		return 0;

	// here we care about this directory and we have to create it's path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	// first write the dentry name
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size)
		     :);
	dlen_offset = 256;
	probe_read(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// now write a "/" after the dentry name
	buffer[dlen_offset + dlen_size] = '/';
	path_size++;

	// write the directory name
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n" ::[dir_size] "+r"(dir_size)
		     :);
	dir_offset = 256 - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n" ::[dir_offset] "+r"(dir_offset)
		     :);
	probe_read(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;

	// check if we care about the new directory
	// if not just not add it in the inode map
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = msg->path.size * 8;
	memcpy(key->data, msg->path.str, 256); // need the rest to be zero-ed

	action = filter_match(key, &rule_id);
	if (action == FILTER_NOTFOUND) // we don't care
		return 0;

	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	// create the event
	msg->action = action_mkdir;
	msg->hook = hook_vfs_mkdir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->digest.ok = 0;

	operation = eval_selectors(action_mkdir);

	// create the mkdir_retprobe_map value and set it for the kretprobe
	fill_mkdir_retprobe_map(ctx, dentry, msg, action, operation);

	return 0;
}

SEC("kprobe/vfs_mkdir/63")
int BPF_KPROBE(vfs_mkdir_v63, struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *dentry, umode_t mode)
{
	kprobe_vfs_mkdir(ctx, dir, dentry, mode);
	return 0;
}

SEC("kprobe/vfs_mkdir/512")
int BPF_KPROBE(vfs_mkdir_v512, struct user_namespace *mnt_userns, struct inode *dir,
	       struct dentry *dentry, umode_t mode)
{
	kprobe_vfs_mkdir(ctx, dir, dentry, mode);
	return 0;
}

SEC("kprobe/vfs_mkdir/419")
int BPF_KPROBE(vfs_mkdir_v419, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	kprobe_vfs_mkdir(ctx, dir, dentry, mode);
	return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(vfs_mkdir_exit, long ret)
{
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	struct vfs_mkdir_info *val;
	struct inode *d_inode;
	struct dentry *dentry;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct msg_file_ops *msg;
	int zero = 0, action = 0;
	__u32 path_size = 0;
	__u32 operation = 0;

	if (ret) {
		if ((val = map_lookup_elem(&mkdir_retprobe_map, &rkey))) {
			struct retprobe_key dkey = {
				.pid_tgid = rkey.pid_tgid,
				.reg = (__u64)val->dentry,
				.flags = LSM_FMOD_KEY,
			};
			map_delete_elem(&mkdir_retprobe_map, &dkey);
		}
		map_delete_elem(&mkdir_retprobe_map, &rkey);
		return 0;
	}

	msg = map_lookup_elem(&file_heap_map, &zero);
	if (!msg)
		return 0;

	val = map_lookup_elem(&mkdir_retprobe_map, &rkey);
	if (!val)
		return 0;

	dentry = val->dentry;
	action = val->action;
	memcpy(msg, &val->msg, sizeof(struct msg_file_ops));
	operation = val->operation;

	// we are done with 'val' so we can delete than entry
	map_delete_elem(&mkdir_retprobe_map, &rkey);
	rkey.reg = (__u64)dentry;
	rkey.flags = LSM_FMOD_KEY;
	map_delete_elem(&mkdir_retprobe_map, &rkey);

	// get current inode and fs info
	// we know that at the kretprobe hook
	probe_read(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode)
		return 0;

	get_ino_fs(msg, d_inode, dentry);

	// and now add this to hash_map_dir_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	file_val->action = action;
	file_val->size = msg->path.size;
	path_size = msg->path.size;
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(file_val->path, path_size, msg->path.str);

	if (msg->path.flags & CONTAINER_FILE) {
		file_val->location_flags = CONTAINER_FILE;
		memcpy(file_val->container_id, msg->path.container_id, CONTAINER_ID_LEN);
	} else {
		file_val->location_flags = HOST_FILE;
	}

	map_update_elem(&hash_map_dir_alloc, &file_key, file_val, 0);

	if (action == FILTER_IGNORE) // due to path_file_exclude
		return 0;
	if (action == FILTER_MONITOR)
		return 0;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid sending the message.
	// In these events have already updated any internal maps.
	if (!(operation & FILE_OP_POST))
		return 0;

	/* operation cannot be FILE_OP_BLOCK here as this operation will 
	 * be block by lsm/fmod_ret programs */
	msg->operation = FILE_OP_POST;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}

#if defined(__FILE_ENFORCE_LSM) || defined(__FILE_ENFORCE_FMOD)
static inline __attribute__((always_inline)) int security_inode_mkdir(void *ctx, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = (__u64)dentry,
		.flags = LSM_FMOD_KEY,
	};
	struct vfs_mkdir_info *val;

	val = map_lookup_elem(&mkdir_retprobe_map, &rkey);
	if (!val)
		return 0;

	if (val->operation & FILE_OP_BLOCK) {
		int zero = 0;
		struct msg_file_ops *msg = map_lookup_elem(&file_heap_map, &zero);
		if (!msg)
			return 0;

		memcpy(msg, &val->msg, sizeof(struct msg_file_ops));
		map_delete_elem(&mkdir_retprobe_map, &rkey);

		msg->hook = hook_security_inode_mkdir;
		msg->operation = FILE_OP_BLOCK;

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

		return -EPERM;
	}
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_mkdir")
int BPF_PROG(security_inode_mkdir_lsm, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return security_inode_mkdir(ctx, dir, dentry, mode);
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_mkdir")
int BPF_PROG(security_inode_mkdir_fmod, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	return security_inode_mkdir(ctx, dir, dentry, mode);
}
#endif
