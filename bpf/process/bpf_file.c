#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "hubble_msg.h"
#include "bpf_events.h"

#include "file.h"
#include "iso_msg_types.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define FILTER_NOTFOUND -1
#define FILTER_IGNORE	0
#define FILTER_MATCH	1

/* generic data direction definitions */
#define READ  0
#define WRITE 1

#define FAULT_FLAG_WRITE   0x01
#define FAULT_FLAG_MKWRITE 0x02

#define VM_READ	 0x00000001
#define VM_WRITE 0x00000002

#define FMODE_CREATED 0x100000

#define PAGE_SIZE 4096

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev)    ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int)((dev)&MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

#define S_IFMT	 00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG	 0100000
#define S_IFBLK	 0060000
#define S_IFDIR	 0040000
#define S_IFCHR	 0020000
#define S_IFIFO	 0010000

#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

// rename flags
#define MOVE_INSIDE	(1 << 0)
#define MOVE_OUTSIDE	(1 << 1)
#define MOVE_INTERNALLY (1 << 2)
#define SRC_REG_FILE	(1 << 3)
#define SRC_DIRECTORY	(1 << 4)
#define SRC_CHAR_DEV	(1 << 5)
#define SRC_BLOCK_DEV	(1 << 6)
#define SRC_NAMED_PIPE	(1 << 7)
#define SRC_SYMLINK	(1 << 8)
#define SRC_SOCKET	(1 << 9)
#define SRC_INVALID	(1 << 10)
#define DST_NOT_EXISTS	(1 << 11)
#define DST_REG_FILE	(1 << 12)
#define DST_DIRECTORY	(1 << 13)
#define DST_CHAR_DEV	(1 << 14)
#define DST_BLOCK_DEV	(1 << 15)
#define DST_NAMED_PIPE	(1 << 16)
#define DST_SYMLINK	(1 << 17)
#define DST_SOCKET	(1 << 18)
#define DST_INVALID	(1 << 19)

struct bpf_map_def __attribute__((section("maps"), used)) mkdir_retprobe_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct vfs_mkdir_info),
	.max_entries = 1024,
};

struct bpf_map_def __attribute__((section("maps"), used))
rename_retprobe_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct vfs_rename_info),
	.max_entries = 1024,
};

struct bpf_map_def __attribute__((section("maps"), used))
vfs_rename_info_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct vfs_rename_info),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
file_rename_heap_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_file_rename_ops),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) file_heap_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_file_ops),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
lpm_trie_map_alloc = { .type = BPF_MAP_TYPE_LPM_TRIE,
		       .key_size = sizeof(struct bpf_lpm_trie_key) + 256,
		       .value_size = sizeof(uint32_t),
		       .max_entries = 4096,
		       .map_flags = BPF_F_NO_PREALLOC };

struct bpf_map_def __attribute__((section("maps"), used)) lpm_trie_heap_key = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct bpf_lpm_trie_key) + 256,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
hash_map_file_alloc = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct hash_map_file_key),
	.value_size = sizeof(struct hash_map_file_val),
	.max_entries = 128 * 1024,
};

struct bpf_map_def __attribute__((section("maps"), used)) hash_map_dir_alloc = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct hash_map_file_key),
	.value_size = sizeof(struct hash_map_file_val),
	.max_entries = 128 * 1024,
};

struct bpf_map_def __attribute__((section("maps"), used)) file_val_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct hash_map_file_val),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) struct msg_file_ops *get_msg_init()
{
	struct msg_file_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_heap_map, &zero);
	if (!msg)
		return 0;

	msg->common.op = ISO_MSG_OP_FILE;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;
	msg->common.size = sizeof(struct msg_file_ops);
	msg->common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}
	msg->current.pad[0] = 0;
	msg->current.pad[1] = 0;
	msg->current.pad[2] = 0;
	msg->current.pad[3] = 0;

	return msg;
}

static inline __attribute__((always_inline)) int
filter_match(struct bpf_lpm_trie_key *key)
{
	uint32_t *retval = map_lookup_elem(&lpm_trie_map_alloc, key);
	if (retval)
		return *retval;
	return FILTER_NOTFOUND;
}

static inline __attribute__((always_inline)) void get_mnt_ns(__u32 *mnt_ns)
{
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct nsproxy nsp;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	probe_read(&nsp, sizeof(nsp), _(nsproxy));
	probe_read(mnt_ns, sizeof(*mnt_ns), _(&nsp.mnt_ns->ns.inum));
}

static inline __attribute__((always_inline)) void
get_fs_info(struct msg_fs_info *msg, struct inode *inode)
{
	struct super_block *sb;
	struct file_system_type *sb_type;
	char *sb_name;

	probe_read(&sb, sizeof(sb), _(&inode->i_sb));
	if (!sb)
		return;

	probe_read(&(msg->dev), sizeof(msg->dev), _(&sb->s_dev));
	msg->pad = 0;
	probe_read(msg->id, 8 * sizeof(char), _(&(sb->s_id[0])));

	probe_read(&sb_type, sizeof(sb_type), _(&sb->s_type));
	if (!sb_type)
		return;

	probe_read(&sb_name, sizeof(sb_name), _(&sb_type->name));
	if (!sb_name)
		return;

	probe_read_str(msg->name, 8 * sizeof(char), sb_name);
	probe_read(msg->uuid, 16 * sizeof(char), _(&sb->s_uuid));
}

static inline __attribute__((always_inline)) void
get_ino_fs(struct msg_file_ops *msg, struct inode *inode)
{
	probe_read(&(msg->ino), sizeof(msg->ino), _(&inode->i_ino));

	get_fs_info(&(msg->fs), inode);
}

#ifndef VFS_PROGS_V512
static inline __attribute__((always_inline)) void
get_parent_ino_fs(struct msg_file_ops *msg, struct dentry *parent_dentry)
{
	struct inode *parent_inode;

	probe_read(&parent_inode, sizeof(parent_inode),
		   _(&parent_dentry->d_inode));
	if (!parent_inode)
		return;

	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino),
		   _(&parent_inode->i_ino));

	get_fs_info(&(msg->parent_fs), parent_inode);
}
#endif

static inline __attribute__((always_inline)) struct hash_map_file_val *
find_inode_in_map(struct bpf_map_def *inode_map, __u64 ino, __u32 dev)
{
	struct hash_map_file_key file_key;

	file_key.ino = ino;
	file_key.dev_major = MAJOR(dev);
	file_key.dev_minor = MINOR(dev);

	return map_lookup_elem(inode_map, &file_key);
}

#ifndef VFS_PROGS_V512
static inline __attribute__((always_inline)) int
handle_generic_file_access(struct pt_regs *ctx, struct file *file, int action,
			   int hook_type, __s64 offset, __u32 iosize)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct path path;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;

	if (!file)
		return 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&file->f_inode));
	if (!inode)
		return 0;

	get_ino_fs(msg, inode);

	// get parent inode and fs info
	probe_read(&path, sizeof(path), _(&file->f_path));
	if (!path.dentry)
		return 0;

	dentry = path.dentry;
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// find this file inside the file inode map
	// we don't care if we cannot find this in the map
	// or the action is FILTER_IGNORE
	file_val =
		find_inode_in_map(&hash_map_file_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action;
	msg->hook = hook_type;
	msg->ktime = ktime_get_ns();
	msg->offset = offset;
	msg->size = iosize;
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
#endif

#ifndef VFS_PROGS_V512
static inline __attribute__((always_inline)) int
handle_generic_file_write(struct pt_regs *ctx, struct file *file, int hook_type,
			  __s64 offset, __u32 size)
{
	return handle_generic_file_access(ctx, file, action_write, hook_type,
					  offset, size);
}
#endif

#ifndef VFS_PROGS_V512
static inline __attribute__((always_inline)) int
handle_generic_file_read(struct pt_regs *ctx, struct file *file, int hook_type,
			 __s64 offset, __u32 size)
{
	return handle_generic_file_access(ctx, file, action_read, hook_type,
					  offset, size);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section("kprobe/vfs_fallocate"), used)) int
BPF_KPROBE(vfs_fallocate, struct file *file, int mode, loff_t offset,
	   loff_t len)
{
	return handle_generic_file_write(ctx, file, hook_vfs_fallocate, offset,
					 len);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section("kprobe/rw_verify_area"), used)) int
BPF_KPROBE(rw_verify_area, int read_write, struct file *file,
	   const loff_t *ppos, size_t count)
{
	__s64 offset;
	probe_read(&offset, sizeof(offset), ppos);

	if (read_write == READ)
		return handle_generic_file_read(ctx, file, hook_rw_verify_area,
						offset, count);
	else // (type == WRITE)
		return handle_generic_file_write(ctx, file, hook_rw_verify_area,
						 offset, count);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section("kprobe/filemap_fault"), used)) int
BPF_KPROBE(filemap_fault, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	__u32 pgoff;
	struct file *file;
	unsigned long flags;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&pgoff, sizeof(pgoff), _(&vmf->pgoff));

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// if we have a write page-fault we also issue a read event
	// as it may happen without any page faults or other actions
	if (flags & VM_WRITE) {
		handle_generic_file_write(ctx, file, hook_filemap_fault,
					  pgoff * PAGE_SIZE,
					  (pgoff + 1) * PAGE_SIZE);
	}
	handle_generic_file_read(ctx, file, hook_filemap_fault,
				 pgoff * PAGE_SIZE, (pgoff + 1) * PAGE_SIZE);

	return 0;
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section("kprobe/filemap_map_pages"), used)) int
BPF_KPROBE(filemap_map_pages, struct vm_fault *vmf, __u32 start_pgoff,
	   __u32 end_pgoff)
{
	struct vm_area_struct *vma;
	unsigned long flags;
	struct file *file;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// generate both events as after a write pgfault we can read
	if (flags & VM_WRITE) {
		handle_generic_file_write(ctx, file, hook_filemap_map_pages,
					  start_pgoff * PAGE_SIZE,
					  (end_pgoff * PAGE_SIZE) + PAGE_SIZE);
	}
	handle_generic_file_read(ctx, file, hook_filemap_map_pages,
				 start_pgoff * PAGE_SIZE,
				 (end_pgoff * PAGE_SIZE) + PAGE_SIZE);

	return 0;
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section("kprobe/filemap_page_mkwrite"), used)) int
BPF_KPROBE(filemap_page_mkwrite, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	__u32 pgoff;
	struct file *file;

	probe_read(&pgoff, sizeof(pgoff), _(&vmf->pgoff));

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	return handle_generic_file_write(ctx, file, hook_filemap_page_mkwrite,
					 pgoff * PAGE_SIZE,
					 (pgoff + 1) * PAGE_SIZE);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section(("kprobe/security_path_unlink")), used)) int
BPF_KPROBE(security_path_unlink, const struct path *dir, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	unsigned int i_nlink = 0;
	bool remove_entry = false;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&inode, sizeof(inode), _(&dentry->d_inode));
	if (!inode)
		return 0;

	get_ino_fs(msg, inode);

	// get parent inode and fs info
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dir->dentry));
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// If inode->i_nlink == 1 (i.e. last link) we should also remove that
	// from hash_map_file_alloc.
	probe_read(&i_nlink, sizeof(i_nlink), _(&inode->i_nlink));
	remove_entry = (i_nlink == 1);

	// find this file inside the file inode map
	// if we cannot find that in map we don't have anything to remove from the map
	file_val =
		find_inode_in_map(&hash_map_file_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;

	// we don't care about that so after the map cleanup we can return
	if (file_val->action == FILTER_IGNORE)
		goto ignore_unlink;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action_delete;
	msg->hook = hook_security_path_unlink;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

ignore_unlink:
	if (remove_entry) {
		file_key.ino = msg->ino;
		file_key.dev_major = MAJOR(msg->fs.dev);
		file_key.dev_minor = MINOR(msg->fs.dev);

		map_delete_elem(&hash_map_file_alloc, &file_key);
	}

	return 0;
}
#endif

#ifndef VFS_PROGS_V512
static inline __attribute__((always_inline)) int
check_file_create(struct pt_regs *ctx, struct file *f, struct inode *inode,
		  struct path *path, __u32 hook)
{
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 f_mode, path_size = 0;
	int zero = 0, action = 0;
	struct qstr d_name;
	char *buffer;

	probe_read(&f_mode, sizeof(f_mode), _(&f->f_mode));
	if ((f_mode & FMODE_CREATED) == 0)
		return 0; // no file created

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	get_ino_fs(msg, inode);

	// get parent inode and fs info
	probe_read(&dentry, sizeof(struct dentry *), _(&path->dentry));
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// find the parent directory entry
	file_val = find_inode_in_map(&hash_map_dir_alloc, msg->parent_ino,
				     msg->parent_fs.dev);
	if (!file_val)
		return 0;
	// we don't care for anything inside this directory
	if (file_val->action == FILTER_IGNORE)
		return 0;

	// we care about files inside this directory
	// get a buffer to generate its path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	// first write the dentry name
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size) :);
	dlen_offset = MAX_FILEPATH_SIZE;
	probe_read(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// then write the directory name
	// this is what we have in the map already (we don't traverse anything)
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n" ::[dir_size] "+r"(dir_size) :);
	dir_offset = MAX_FILEPATH_SIZE - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n" ::[dir_offset] "+r"(dir_offset)
		     :);
	probe_read(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	// set the filepath inside msg
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size) :);
	probe_read(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;

	// although we care about files inside this directory
	// we may have this specific file path in the exclude
	// list now we check the trie with the initial paths
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = msg->path.size * 8;
	memcpy(key->data, msg->path.str, 256);

	action = filter_match(key);
	if (action == FILTER_NOTFOUND || action == FILTER_IGNORE)
		return 0; // we don't care

	// and insert that inode to the hash_map_file_alloc
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

	// add this new file to the map of files
	map_update_elem(&hash_map_file_alloc, &file_key, file_val, 0);

	probe_read(&(msg->imode), sizeof(msg->imode), _(&inode->i_mode));
	msg->pad1 = msg->pad2 = 0;
	probe_read(&(msg->uid), sizeof(msg->uid), _(&inode->i_uid));
	probe_read(&(msg->gid), sizeof(msg->gid), _(&inode->i_gid));

	msg->action = action_create;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}

__attribute__((section(("kprobe/finish_open")), used)) int
BPF_KPROBE(finish_open, struct file *file, struct dentry *dentry,
	   int (*open)(struct inode *, struct file *))
{
	struct inode *inode;

	probe_read(&inode, sizeof(struct inode *), _(&dentry->d_inode));
	if (!inode)
		return 0;

	return check_file_create(ctx, file, inode, _(&file->f_path),
				 hook_finish_open);
}

__attribute__((section(("kprobe/vfs_open")), used)) int
BPF_KPROBE(vfs_open, const struct path *path, struct file *file)
{
	struct dentry *dentry;
	struct inode *inode;

	probe_read(&dentry, sizeof(struct dentry *), _(&path->dentry));
	if (!dentry)
		return 0;

	probe_read(&inode, sizeof(struct inode *), _(&dentry->d_inode));
	if (!inode)
		return 0;

	return check_file_create(ctx, file, inode, (struct path *)path,
				 hook_vfs_open);
}
#endif

static inline __attribute__((always_inline)) int
kprobe_vfs_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
	struct inode *d_inode;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct msg_file_ops *msg;

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&d_inode, sizeof(d_inode), _(&dentry->d_inode));
	if (!d_inode)
		return 0;

	get_ino_fs(msg, d_inode);

	// get parent inode and fs info
	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino), _(&dir->i_ino));
	get_fs_info(&(msg->parent_fs), dir);

	// check if we care about this directory
	file_val =
		find_inode_in_map(&hash_map_dir_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;

	if (file_val->action == FILTER_IGNORE)
		goto ignore_rmdir;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;

	msg->action = action_rmdir;
	msg->hook = hook_vfs_rmdir;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

ignore_rmdir:
	// delete this directory from the map with directories
	// that we are watching
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	map_delete_elem(&hash_map_dir_alloc, &file_key);

	return 0;
}

#ifdef VFS_PROGS_V512
__attribute__((section(("kprobe/vfs_rmdir")), used)) int
BPF_KPROBE(vfs_rmdir, struct user_namespace *mnt_userns, struct inode *dir,
	   struct dentry *dentry)
{
	return kprobe_vfs_rmdir(ctx, dir, dentry);
}
#else
__attribute__((section(("kprobe/vfs_rmdir")), used)) int
BPF_KPROBE(vfs_rmdir, struct inode *dir, struct dentry *dentry)
{
	return kprobe_vfs_rmdir(ctx, dir, dentry);
}
#endif

static inline __attribute__((always_inline)) int
kprobe_vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct vfs_mkdir_info value;

	value.inode = dir;
	value.dentry = dentry;

	map_update_elem(&mkdir_retprobe_map, &pid_tgid, &value, 0);

	return 0;
}

#ifdef VFS_PROGS_V512
__attribute__((section(("kprobe/vfs_mkdir")), used)) int
BPF_KPROBE(vfs_mkdir, struct user_namespace *mnt_userns, struct inode *dir,
	   struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(dir, dentry, mode);
}
#else
__attribute__((section(("kprobe/vfs_mkdir")), used)) int
BPF_KPROBE(vfs_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return kprobe_vfs_mkdir(dir, dentry, mode);
}
#endif

#ifndef VFS_PROGS_V512
__attribute__((section(("kretprobe/vfs_mkdir")), used)) int
BPF_KRETPROBE(vfs_mkdir_exit, long ret)
{
	u64 pid_tgid = get_current_pid_tgid();
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
		map_delete_elem(&mkdir_retprobe_map, &pid_tgid);
		return 0;
	}

	val = map_lookup_elem(&mkdir_retprobe_map, &pid_tgid);
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

	file_val = find_inode_in_map(&hash_map_dir_alloc, msg->parent_ino,
				     msg->parent_fs.dev);
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

/*
 * For the rename operation, we hook into four points:
 *   1. kprobe/security_path_rename: Store the old/new path using the thread id.
 *      We need that for the case where the src or dst directory is not in the
 *      watched path. For the watched paths we use hash_map_dir_alloc to get
 *      the directory path based on its inode number.
 *   2. kretprobe/security_path_rename: In the case where security_path_rename
 *      fails (i.e. not enough permissions) we just cleanup vfs_rename_info_heap
 *      and return.
 *   3. kprobe/vfs_rename: We determine the details of the rename operation and
 *      check whether we are interested in either the source or destination inode.
 *   4. kretprobe/vfs_rename: If operation is succesful, we generate the path for
 *      a directory that is not watched (if needed), update our maps, and generate
 *      the rename event.
 *
 * Based on that we track only vfs_rename calls that come after security_path_rename
 * calls. There are 3 cases where this is not the case:
 *   1. in-kernel NFS server
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/nfsd/vfs.c#L1790)
 *   2. ecryptfs that seems to be a stackable filesystem and its rename operation is just
 *      to call again vfs_rename with the underlying inode/dentry.
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/ecryptfs/inode.c#L622)
 *   3. overlayfs which is a stackable filesystem. We will get the rename event for
 *      the overlayfs and then it will call vfs_rename again using the undelying
 *      inode/dentry.
 *      (https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/dir.c#L1072 and
 *      https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/overlayfs.h#L210)
 */
__attribute__((section(("kprobe/security_path_rename")), used)) int
BPF_KPROBE(security_path_rename, const struct path *old_dir,
	   struct dentry *old_dentry, const struct path *new_dir,
	   struct dentry *new_dentry, unsigned int flags)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct vfs_rename_info *v;
	int zero = 0;

	v = map_lookup_elem(&vfs_rename_info_heap, &zero);
	if (!v)
		return 0;

	v->old_dir = old_dir;
	v->new_dir = new_dir;
	v->need_old = 0;
	v->need_new = 0;

	map_update_elem(&rename_retprobe_map, &pid_tgid, v, 0);
	return 0;
}

__attribute__((section(("kretprobe/security_path_rename")), used)) int
BPF_KRETPROBE(security_path_rename_exit, long ret)
{
	if (ret) {
		u64 pid_tgid = get_current_pid_tgid();
		map_delete_elem(&rename_retprobe_map, &pid_tgid);
	}
	return 0;
}

static inline __attribute__((always_inline)) void
rename_copy_dname(struct dentry *dentry, struct msg_rename_elem *pth)
{
	struct qstr d_name;
	__u32 dlen_size = 0;

	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size) :);
	probe_read(pth->path.name, dlen_size, (const char *)d_name.name);
	pth->path.name_size = dlen_size;
}

static inline __attribute__((always_inline)) int
kprobe_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		  struct inode *new_dir, struct dentry *new_dentry,
		  struct inode **delegated_inode /*, unsigned int flags */)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct vfs_rename_info *v;
	struct inode *d_inode;
	bool walker = 0;
	struct execve_map_value *enter;
	__u32 ppid;
	umode_t i_mode;

	v = map_lookup_elem(&rename_retprobe_map, &pid_tgid);
	if (!v) // If not found just return. This is a call to vfs_rename without a previous call to security_path_rename so something kernel internal.
		return 0;

	v->msg.common.op = ISO_MSG_OP_FILE_RENAME;
	v->msg.common.flags = 0;
	v->msg.common.pad[0] = 0;
	v->msg.common.pad[1] = 0;
	v->msg.common.size = sizeof(struct msg_file_rename_ops);
	v->msg.common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		v->msg.current.pid = enter->key.pid;
		v->msg.current.ktime = enter->key.ktime;
	}
	v->msg.current.pad[0] = 0;
	v->msg.current.pad[1] = 0;
	v->msg.current.pad[2] = 0;
	v->msg.current.pad[3] = 0;

	v->msg.flags = 0;

	// get current inode and fs info for src (old)
	probe_read(&d_inode, sizeof(d_inode), _(&old_dentry->d_inode));
	probe_read(&(v->msg.src.ino), sizeof(v->msg.src.ino),
		   _(&d_inode->i_ino));
	probe_read(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
	get_fs_info(&(v->msg.src.fs), d_inode);

	if (S_ISREG(i_mode))
		v->msg.flags |= SRC_REG_FILE;
	else if (S_ISDIR(i_mode))
		v->msg.flags |= SRC_DIRECTORY;
	else if (S_ISCHR(i_mode))
		v->msg.flags |= SRC_CHAR_DEV;
	else if (S_ISBLK(i_mode))
		v->msg.flags |= SRC_BLOCK_DEV;
	else if (S_ISFIFO(i_mode))
		v->msg.flags |= SRC_NAMED_PIPE;
	else if (S_ISLNK(i_mode))
		v->msg.flags |= SRC_SYMLINK;
	else if (S_ISSOCK(i_mode))
		v->msg.flags |= SRC_SOCKET;
	else
		v->msg.flags |= SRC_INVALID;

	// get parent inode and fs info for src (old)
	probe_read(&(v->msg.src.parent_ino), sizeof(v->msg.src.parent_ino),
		   _(&old_dir->i_ino));
	get_fs_info(&(v->msg.src.parent_fs), old_dir);

	// get current inode and fs info for dst (new)
	probe_read(&d_inode, sizeof(d_inode), _(&new_dentry->d_inode));
	if (d_inode == 0) {
		v->msg.dst.ino = 0;
		v->msg.flags |= DST_NOT_EXISTS;
	} else {
		probe_read(&(v->msg.dst.ino), sizeof(v->msg.dst.ino),
			   _(&d_inode->i_ino));
		probe_read(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
		get_fs_info(&(v->msg.dst.fs), d_inode);

		if (S_ISREG(i_mode))
			v->msg.flags |= DST_REG_FILE;
		else if (S_ISDIR(i_mode))
			v->msg.flags |= DST_DIRECTORY;
		else if (S_ISCHR(i_mode))
			v->msg.flags |= DST_CHAR_DEV;
		else if (S_ISBLK(i_mode))
			v->msg.flags |= DST_BLOCK_DEV;
		else if (S_ISFIFO(i_mode))
			v->msg.flags |= DST_NAMED_PIPE;
		else if (S_ISLNK(i_mode))
			v->msg.flags |= DST_SYMLINK;
		else if (S_ISSOCK(i_mode))
			v->msg.flags |= DST_SOCKET;
		else
			v->msg.flags |= DST_INVALID;
	}

	// get parent inode and fs info for dst (new)
	probe_read(&(v->msg.dst.parent_ino), sizeof(v->msg.dst.parent_ino),
		   _(&new_dir->i_ino));
	get_fs_info(&(v->msg.dst.parent_fs), new_dir);

	// optimization: try to avoid doing path resolution and path copies
	// if we don't care both for src and dst
	{
		__u32 src_watched = 0, dst_watched = 0;
		struct hash_map_file_val *fv;

		if ((v->msg.flags & SRC_REG_FILE) ||
		    (v->msg.flags & SRC_DIRECTORY)) {
			fv = find_inode_in_map(&hash_map_dir_alloc,
					       v->msg.src.parent_ino,
					       v->msg.src.parent_fs.dev);
			if (fv && fv->action == FILTER_MATCH)
				src_watched = 1;
		}

		if ((v->msg.flags & DST_REG_FILE) ||
		    (v->msg.flags & DST_DIRECTORY) ||
		    (v->msg.flags & DST_NOT_EXISTS)) {
			fv = find_inode_in_map(&hash_map_dir_alloc,
					       v->msg.dst.parent_ino,
					       v->msg.dst.parent_fs.dev);
			if (fv && fv->action == FILTER_MATCH)
				dst_watched = 1;
		}

		if (!src_watched && !dst_watched) {
			map_delete_elem(&rename_retprobe_map, &pid_tgid);
			return 0;
		}
	}

	// check if we care about src and get path for src (old)
	{
		struct hash_map_file_val *fval = 0;

		if ((v->msg.flags & SRC_REG_FILE) ||
		    (v->msg.flags & SRC_DIRECTORY)) {
			fval = find_inode_in_map(&hash_map_dir_alloc,
						 v->msg.src.parent_ino,
						 v->msg.src.parent_fs.dev);
		} // otherwise we don't care

		if (fval == 0) { // we care for the path not for the action
			v->need_old = 1;
		} else {
			memcpy(v->msg.src.path.dir, fval->path, 256);
			v->msg.src.path.dir_size = fval->size;
			v->msg.src.path.flags = 0;
		}

		rename_copy_dname(old_dentry, &(v->msg.src));
		v->msg.src.pad = 0;
	}

	// get path for dst (new)
	{
		struct hash_map_file_val *fval = 0;

		if ((v->msg.flags & DST_REG_FILE) ||
		    (v->msg.flags & DST_DIRECTORY) ||
		    (v->msg.flags & DST_NOT_EXISTS)) {
			fval = find_inode_in_map(&hash_map_dir_alloc,
						 v->msg.dst.parent_ino,
						 v->msg.dst.parent_fs.dev);
		} // otherwise we don't care

		if (fval == 0) { // we care for the path not for the action
			v->need_new = 1;
		} else {
			memcpy(v->msg.dst.path.dir, fval->path, 256);
			v->msg.dst.path.dir_size = fval->size;
			v->msg.dst.path.flags = 0;
		}

		rename_copy_dname(new_dentry, &(v->msg.dst));
		v->msg.dst.pad = 0;
	}

	if (v->need_old) {
		if (v->need_new) {
			map_delete_elem(&rename_retprobe_map, &pid_tgid);
			return 0;
		}
		v->msg.flags |= MOVE_INSIDE;
	} else {
		v->msg.flags |=
			(v->need_new == 0) ? (MOVE_INTERNALLY) : (MOVE_OUTSIDE);
	}

	// create the event
	v->msg.action = action_rename;
	v->msg.hook = hook_vfs_rename;
	v->msg.ktime = ktime_get_ns();
	get_mnt_ns(&v->msg.mnt_ns);

	return 0;
}

#ifdef VFS_PROGS_V512
struct renamedata {
	struct user_namespace *old_mnt_userns;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct user_namespace *new_mnt_userns;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
} __randomize_layout;

__attribute__((section(("kprobe/vfs_rename")), used)) int
BPF_KPROBE(vfs_rename, struct renamedata *rd)
{
	struct renamedata d;
	probe_read(&d, sizeof(struct renamedata), rd);
	return kprobe_vfs_rename(d.old_dir, d.old_dentry, d.new_dir,
				 d.new_dentry, d.delegated_inode);
}
#else
__attribute__((section(("kprobe/vfs_rename")), used)) int
BPF_KPROBE(vfs_rename, struct inode *old_dir, struct dentry *old_dentry,
	   struct inode *new_dir, struct dentry *new_dentry,
	   struct inode **delegated_inode /*, unsigned int flags */)
{
	return kprobe_vfs_rename(old_dir, old_dentry, new_dir, new_dentry,
				 delegated_inode);
}
#endif

static inline __attribute__((always_inline)) void
resolve_missed_paths(struct vfs_rename_info *val)
{
	const struct path *res_path = 0;
	struct msg_rename_elem *pth = 0;

	// if none is 1 then res_path == 0 and we don't need to resolve any paths
	// there will be no case where both (need_old == 1) && (need_new == 1)
	if (val->need_old) {
		res_path = val->old_dir;
		pth = &(val->msg.src);
	} else if (val->need_new) {
		res_path = val->new_dir;
		pth = &(val->msg.dst);
	}

	if (res_path) {
		int buflen, error;
		char *buf = d_path_local(res_path, &buflen, &error);
		if (buf == 0)
			return;

		memcpy(pth->path.dir, buf, 256);
		pth->path.dir_size = buflen;
		pth->path.flags = error;
	}
}

static inline __attribute__((always_inline)) void
remove_inode_rename(struct msg_rename_elem *v)
{
	struct hash_map_file_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	map_delete_elem(&hash_map_file_alloc, &file_key);
}

static inline __attribute__((always_inline)) void
update_inode_rename(struct msg_rename_elem *v,
		    struct hash_map_file_val *file_val)
{
	struct hash_map_file_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	map_update_elem(&hash_map_file_alloc, &file_key, file_val, 0);
}

static inline __attribute__((always_inline)) struct hash_map_file_val *
generate_file_val(struct msg_rename_elem *dir, struct msg_rename_elem *name)
{
	struct hash_map_file_val *file_val = 0;
	struct hash_map_file_val *dir_val = 0;
	int zero = 0;
	char *buf = 0;
	__u32 dir_size, name_size;

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	// we can also get this from val->msg.src.path.dir but we have also to append a '/'
	// which makes that a bit more complex in ebpf
	dir_val = find_inode_in_map(&hash_map_dir_alloc, dir->parent_ino,
				    dir->parent_fs.dev);
	if (!dir_val)
		return 0;
	// we need that in order to generate the path so don't return if
	// action is FILTER_IGNORE

	buf = &(file_val->path[0]);

	// file_val->path is 256 bytes
	// next, we will limit dir to be up to 192 bytes and name up to 64 bytes

	// copy parent directory path (including '/')
	dir_size = dir_val->size;
	asm volatile("%[dir_size] &= 0xbf;\n" ::[dir_size] "+r"(dir_size) :);
	probe_read(buf, dir_size, dir_val->path);
	file_val->size = dir_size;

	// copy file name
	name_size = name->path.name_size;
	asm volatile("%[name_size] &= 0x3f;\n" ::[name_size] "+r"(name_size) :);
	probe_read(buf + dir_size, name_size, name->path.name);
	file_val->size += name_size;

	return file_val;
}

// we have to consider what we need to do (i.e. what we can handle here and what we need helf from the user-space)
//
// [NOOP]
// SRC_DIRECTORY - MOVE_INSIDE - DST_REG_FILE       // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_REG_FILE      // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_REG_FILE   // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY   // not possible(?) -- if possible nothing to do
// SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY       // not possible(?) -- if possible do it in eBPF
// SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY      // not possible(?) -- if possible do it in eBPF
//
// [GOLANG]
// SRC_DIRECTORY - MOVE_INSIDE - DST_NOT_EXISTS     // traverse dst.filename and add everything to both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_INSIDE - DST_DIRECTORY      // traverse dst.filename and add everything to both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_NOT_EXISTS    // traverse dst.filename and remove everything from both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_DIRECTORY     // traverse dst.filename and remove everything from both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_NOT_EXISTS // traverse dst.filename and update names in hash_map_dir_alloc only
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_DIRECTORY  // traverse dst.filename and update names in hash_map_dir_alloc only
//
// [EBPF]
// SRC_REG_FILE - MOVE_INSIDE - DST_NOT_EXISTS      // add add src.inode to hash_map_file_alloc
// SRC_REG_FILE - MOVE_INSIDE - DST_REG_FILE        // remove dst.inode from hash_map_file_alloc *and* src.inode to hash_map_file_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_NOT_EXISTS     // remove src.inode from hash_map_file_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_REG_FILE       // remove src.inode from hash_map_file_alloc
// SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS  // add add src.inode to hash_map_file_alloc to update the path
// SRC_REG_FILE - MOVE_INTERNALLY - DST_REG_FILE    // remove dst.inode from hash_map_file_alloc *and* src.inode to hash_map_file_alloc to update the path
__attribute__((section(("kretprobe/vfs_rename")), used)) int
BPF_KRETPROBE(vfs_rename_exit, long ret)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct vfs_rename_info *val;
	struct msg_file_rename_ops *msg;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	int zero = 0, action = 0;

	// rename failed
	if (ret) {
		map_delete_elem(&rename_retprobe_map, &pid_tgid);
		return 0;
	}

	// check for the metadata from the kprobe
	val = map_lookup_elem(&rename_retprobe_map, &pid_tgid);
	if (!val)
		return 0;

	// resolve any paths (if needed) for items outside of watched path
	resolve_missed_paths(val);

	if (val->msg.flags & SRC_REG_FILE) {
		if (val->msg.flags & MOVE_INSIDE) {
			// remove dst.inode from hash_map_file_alloc
			if (val->msg.flags & DST_REG_FILE) {
				remove_inode_rename(&(val->msg.dst));
			}

			// add add src.inode to hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				file_val = generate_file_val(&(val->msg.dst),
							     &(val->msg.src));
				if (!file_val)
					return 0;

				// check if we care about the new file
				// if not just not add it in the inode map
				key = map_lookup_elem(&lpm_trie_heap_key,
						      &zero);
				if (!key)
					return 0;

				key->prefixlen = file_val->size * 8;
				memcpy(key->data, file_val->path, 256);

				action = filter_match(key);
				file_val->action = action;

				update_inode_rename(&(val->msg.src), file_val);
			}
		} else if (val->msg.flags & MOVE_INTERNALLY) {
			// remove dst.inode from hash_map_file_alloc
			if (val->msg.flags & DST_REG_FILE) {
				remove_inode_rename(&(val->msg.dst));
			}

			// add add src.inode to hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				file_val = generate_file_val(&(val->msg.src),
							     &(val->msg.dst));
				if (!file_val)
					return 0;

				// check if we care about the new file
				// if not just not add it in the inode map
				key = map_lookup_elem(&lpm_trie_heap_key,
						      &zero);
				if (!key)
					return 0;

				key->prefixlen = file_val->size * 8;
				memcpy(key->data, file_val->path, 256);

				action = filter_match(key);
				file_val->action = action;

				update_inode_rename(&(val->msg.src), file_val);
			}
		} else if (val->msg.flags & MOVE_OUTSIDE) {
			// remove src.inode from hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				remove_inode_rename(&(val->msg.src));
			}
		}
	}

	// now we are all done, so create the meesage to send
	msg = map_lookup_elem(&file_rename_heap_map, &zero);
	if (!msg)
		return 0;

	// a single memcpy does not work
	// "in function event_vfs_rename_ret i32 (%struct.pt_regs*): A call to built-in function 'memcpy' is not supported."
	// memcpy(msg, &(val->msg), sizeof(struct msg_file_rename_ops));
	memcpy(&(msg->common), &(val->msg.common), sizeof(struct msg_common));
	memcpy(&(msg->current), &(val->msg.current),
	       sizeof(struct msg_execve_key));
	msg->action = val->msg.action;
	msg->hook = val->msg.hook;
	msg->ktime = val->msg.ktime;
	memcpy(&(msg->src), &(val->msg.src), sizeof(struct msg_rename_elem));
	memcpy(&(msg->dst), &(val->msg.dst), sizeof(struct msg_rename_elem));
	msg->mnt_ns = val->msg.mnt_ns;
	msg->flags = val->msg.flags;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_rename_ops));

	return 0;
}
