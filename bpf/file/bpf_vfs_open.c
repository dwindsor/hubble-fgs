#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

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
