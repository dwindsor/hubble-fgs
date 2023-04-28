#include "bpf_file.h"
#include "check_file_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file)
{
	struct dentry *dentry;

	probe_read(&dentry, sizeof(struct dentry *), _(&path->dentry));
	if (!dentry)
		return 0;

	check_file_create(ctx, file, dentry, hook_vfs_open);
	return 0;
}