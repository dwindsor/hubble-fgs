#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) int
kprobe_vfs_mkdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry,
		 umode_t mode)
{
	struct retprobe_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	struct vfs_mkdir_info value = {
		.inode = dir,
		.dentry = dentry,
	};

	map_update_elem(&mkdir_retprobe_map, &key, &value, 0);

	return 0;
}

#ifdef VFS_PROGS_V512
__attribute__((section(("kprobe/vfs_mkdir")), used)) int
BPF_KPROBE(vfs_mkdir, struct user_namespace *mnt_userns, struct inode *dir,
	   struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(ctx, dir, dentry, mode);
}
#else
__attribute__((section(("kprobe/vfs_mkdir")), used)) int
BPF_KPROBE(vfs_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(ctx, dir, dentry, mode);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section(("kretprobe/vfs_mkdir")), used)) int
BPF_KRETPROBE(vfs_mkdir_exit, long ret)
{
	struct retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	struct vfs_mkdir_info *val;
	struct inode *inode, *d_inode;
	struct dentry *dentry;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	struct msg_file_ops *msg;
	int zero = 0, action = 0;
	char *buffer;
	__u32 path_size = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	struct qstr d_name;

	if (ret) {
		map_delete_elem(&mkdir_retprobe_map, &rkey);
		return 0;
	}

	val = map_lookup_elem(&mkdir_retprobe_map, &rkey);
	if (!val)
		return 0;

	inode = val->inode;
	dentry = val->dentry;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode)
		return 0;

	get_ino_fs(msg, d_inode);

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino),
		   _(&inode->i_ino));
	get_fs_info(&(msg->parent_fs), inode);

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
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size) :);
	dlen_offset = 256;
	probe_read(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// now write a "/" after the dentry name
	buffer[dlen_offset + dlen_size] = '/';
	path_size++;

	// write the directory name
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n" ::[dir_size] "+r"(dir_size) :);
	dir_offset = 256 - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n" ::[dir_offset] "+r"(dir_offset)
		     :);
	probe_read(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size) :);
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
	if (action == FILTER_NOTFOUND)
		return 0; // we don't care

	// and now add this to hash_map_dir_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	file_val->action = action;
	file_val->size = msg->path.size;
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size) :);
	probe_read(file_val->path, path_size, msg->path.str);

	map_update_elem(&hash_map_dir_alloc, &file_key, file_val, 0);

	if (action == FILTER_IGNORE)
		return 0;

	// create the event
	msg->action = action_mkdir;
	msg->hook = hook_vfs_mkdir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
#endif
