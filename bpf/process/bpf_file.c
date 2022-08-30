#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"

#include "file.h"
#include "iso_msg_types.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define FILTER_IGNORE 0
#define FILTER_MATCH  1

/* generic data direction definitions */
#define READ  0
#define WRITE 1

#define FAULT_FLAG_WRITE   0x01
#define FAULT_FLAG_MKWRITE 0x02

#define VM_READ	 0x00000001
#define VM_WRITE 0x00000002

#define FMODE_CREATED 0x100000

#define ARG0(ctx) (&(ctx->di))
#define ARG1(ctx) (&(ctx->si))
#define ARG2(ctx) (&(ctx->dx))
#define ARG3(ctx) (&(ctx->cx))
#define ARG4(ctx) (&(ctx->r8))

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
	if (retval) {
		if (*retval == FILTER_IGNORE)
			return 0;
	} else {
		return 0; // cannot find -> not a match
	}
	return 1;
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

static inline __attribute__((always_inline)) int
handle_generic_file_access(struct pt_regs *ctx, struct file *file, int action,
			   int hook_type)
{
	struct inode *inode;
	struct msg_file_ops *msg;
	struct bpf_lpm_trie_key *key;
	int zero = 0, size, flags = 0;
	char *buffer;
	struct dentry *dentry, *parent_dentry;
	struct path path;

	if (!file)
		return 0;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	size = 256;
	buffer = __d_path_local(_(&file->f_path), buffer, &size, &flags);
	if (size > 0)
		size = 256 - size;
	if (size < 0)
		size = 0;

	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = size * 8;
	memcpy(key->data, buffer, 256); // need the rest to be zero-ed

	if (!filter_match(key))
		return 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	memcpy(msg->path.str, buffer, 256);
	msg->path.size = size;
	msg->path.flags = flags;

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

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action;
	msg->hook = hook_type;
	msg->ktime = ktime_get_ns();

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}

static inline __attribute__((always_inline)) int
handle_generic_file_write(struct pt_regs *ctx, struct file *file, int hook_type)
{
	return handle_generic_file_access(ctx, file, action_write, hook_type);
}

static inline __attribute__((always_inline)) int
handle_generic_file_read(struct pt_regs *ctx, struct file *file, int hook_type)
{
	return handle_generic_file_access(ctx, file, action_read, hook_type);
}

// int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len) // (W)
__attribute__((section("kprobe/vfs_fallocate"), used)) int
event_vfs_fallocate(struct pt_regs *ctx)
{
	struct file *file;
	probe_read(&file, sizeof(file), ARG0(ctx));
	if (!file)
		return 0;
	return handle_generic_file_write(ctx, file, hook_vfs_fallocate);
}

// int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count) // (R|w)
__attribute__((section("kprobe/rw_verify_area"), used)) int
event_rw_verify_area(struct pt_regs *ctx)
{
	int read_write;
	struct file *file;

	probe_read(&read_write, sizeof(read_write), ARG0(ctx));

	probe_read(&file, sizeof(file), ARG1(ctx));
	if (!file)
		return 0;

	if (read_write == READ)
		return handle_generic_file_read(ctx, file, hook_rw_verify_area);
	else // (type == WRITE)
		return handle_generic_file_write(ctx, file,
						 hook_rw_verify_area);
}

// vm_fault_t filemap_fault(struct vm_fault *vmf) // (R)
__attribute__((section("kprobe/filemap_fault"), used)) int
event_filemap_fault(struct pt_regs *ctx)
{
	struct vm_fault *vmf;
	struct vm_area_struct *vma;
	struct file *file;
	unsigned long flags;

	probe_read(&vmf, sizeof(vmf), ARG0(ctx));
	if (!vmf)
		return 0;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// if we have a write page-fault we also issue a read event
	// as it may happen without any page faults or other actions
	if (flags & VM_WRITE) {
		handle_generic_file_write(ctx, file, hook_filemap_fault);
	}
	handle_generic_file_read(ctx, file, hook_filemap_fault);

	return 0;
}

// void filemap_map_pages(struct vm_fault *vmf, pgoff_t start_pgoff, pgoff_t end_pgoff) // (R)
__attribute__((section("kprobe/filemap_map_pages"), used)) int
event_filemap_map_pages(struct pt_regs *ctx)
{
	struct vm_fault *vmf;
	struct vm_area_struct *vma;
	unsigned long flags;
	struct file *file;

	probe_read(&vmf, sizeof(vmf), ARG0(ctx));
	if (!vmf)
		return 0;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// generate both events as after a write pgfault we can read
	if (flags & VM_WRITE) {
		handle_generic_file_write(ctx, file, hook_filemap_map_pages);
	}
	handle_generic_file_read(ctx, file, hook_filemap_map_pages);

	return 0;
}

// vm_fault_t filemap_page_mkwrite(struct vm_fault *vmf) // (W)
__attribute__((section("kprobe/filemap_page_mkwrite"), used)) int
event_filemap_page_mkwrite(struct pt_regs *ctx)
{
	struct vm_fault *vmf;
	struct vm_area_struct *vma;
	struct file *file;

	probe_read(&vmf, sizeof(vmf), ARG0(ctx));
	if (!vmf)
		return 0;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	return handle_generic_file_write(ctx, file, hook_filemap_page_mkwrite);
}

// int security_path_unlink(const struct path *dir, struct dentry *dentry)
__attribute__((section(("kprobe/security_path_unlink")), used)) int
event_security_path_unlink(struct pt_regs *ctx)
{
	struct path *dir;
	struct dentry *dentry, *parent_dentry;
	struct inode *inode;
	struct qstr d_name;
	struct msg_file_ops *msg;
	int zero = 0, size, flags = 0, d_len;
	char *buffer, *obuffer;
	struct bpf_lpm_trie_key *key;

	probe_read(&dir, sizeof(dir), ARG0(ctx));
	if (!dir)
		return 0;

	probe_read(&dentry, sizeof(dentry), ARG1(ctx));
	if (!dentry)
		return 0;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	d_len = d_name.len + 1;
	size = 256 + d_len;
	obuffer = buffer + size;
	prepend_name(buffer, &obuffer, &size, (const char *)d_name.name,
		     d_name.len);

	size = 256;
	buffer = __d_path_local(dir, buffer, &size, &flags);
	if (size > 0)
		size = 256 - size;
	if (size < 0)
		size = 0;

	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = (size + d_len) * 8;
	memcpy(key->data, buffer, 256); // need the rest to be zero-ed

	if (!filter_match(key))
		return 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	memcpy(msg->path.str, buffer, 256);
	msg->path.size = size + d_len;
	msg->path.flags = flags;

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

	msg->imode = 0;
	msg->pad1 = msg->pad2 = 0;
	msg->uid = msg->gid = 0;

	msg->action = action_delete;
	msg->hook = hook_security_path_unlink;
	msg->ktime = ktime_get_ns();

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}

// int do_dentry_open(struct file *f, struct inode *inode, int (*open)(struct inode *, struct file *))
__attribute__((section(("kprobe/do_dentry_open")), used)) int
event_do_dentry_open(struct pt_regs *ctx)
{
	struct file *file;
	struct inode *inode;
	struct msg_file_ops *msg;
	struct bpf_lpm_trie_key *key;
	int zero = 0, size, flags = 0;
	char *buffer;
	__u32 f_mode;
	struct dentry *dentry, *parent_dentry;
	struct path path;

	probe_read(&file, sizeof(file), ARG0(ctx));
	if (!file)
		return 0;

	probe_read(&inode, sizeof(inode), ARG1(ctx));
	if (!inode)
		return 0;

	probe_read(&f_mode, sizeof(f_mode), _(&file->f_mode));
	if ((f_mode & FMODE_CREATED) == 0)
		return 0; // no file created

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	size = 256;
	buffer = __d_path_local(_(&file->f_path), buffer, &size, &flags);
	if (size > 0)
		size = 256 - size;
	if (size < 0)
		size = 0;

	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = size * 8;
	memcpy(key->data, buffer, 256); // need the rest to be zero-ed

	if (!filter_match(key))
		return 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	memcpy(msg->path.str, buffer, 256);
	msg->path.size = size;
	msg->path.flags = flags;

	// get current inode and fs info
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

	probe_read(&(msg->imode), sizeof(msg->imode), _(&inode->i_mode));
	msg->pad1 = msg->pad2 = 0;
	probe_read(&(msg->uid), sizeof(msg->uid), _(&inode->i_uid));
	probe_read(&(msg->gid), sizeof(msg->gid), _(&inode->i_gid));

	msg->action = action_create;
	msg->hook = hook_do_dentry_open;
	msg->ktime = ktime_get_ns();

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
