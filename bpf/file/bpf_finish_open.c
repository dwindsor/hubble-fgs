#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

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
