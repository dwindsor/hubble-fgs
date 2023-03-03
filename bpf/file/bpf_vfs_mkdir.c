#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) void
fill_mkdir_retprobe_map(struct pt_regs *ctx, struct dentry *dentry, struct msg_file_ops *msg, int action)
{
	struct vfs_mkdir_info *value;
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	int zero = 0;

	value = map_lookup_elem(&vfs_mkdir_info_heap, &zero);
	if (!value)
		return;

	value->dentry = dentry;
	memcpy(&value->msg, msg, sizeof(struct msg_file_ops));
	value->action = action;

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

	action = filter_match(key);
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

	// create the mkdir_retprobe_map value and set it for the kretprobe
	fill_mkdir_retprobe_map(ctx, dentry, msg, action);

	return 0;
}

__attribute__((section(("kprobe/vfs_mkdir/512")), used)) int
BPF_KPROBE(vfs_mkdir_v512, struct user_namespace *mnt_userns, struct inode *dir,
	   struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(ctx, dir, dentry, mode);
}

__attribute__((section(("kprobe/vfs_mkdir/419")), used)) int
BPF_KPROBE(vfs_mkdir_v419, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(ctx, dir, dentry, mode);
}

__attribute__((section(("kretprobe/vfs_mkdir")), used)) int
BPF_KRETPROBE(vfs_mkdir_exit, long ret)
{
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	struct vfs_mkdir_info *val;
	struct inode *d_inode;
	struct dentry *dentry;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct msg_file_ops *msg;
	int zero = 0, action = 0;
	__u32 path_size = 0;

	if (ret) {
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

	// we are done with 'val' so we can delete than entry
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

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
