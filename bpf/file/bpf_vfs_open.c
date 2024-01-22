#include "bpf_file.h"
#include "check_file_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file)
{
	struct dentry *dentry;
	int err;

	probe_read(&dentry, sizeof(struct dentry *), _(&path->dentry));
	if (!dentry) {
		err = -FILE_ERR_DENTRY_FROM_PATH;
		goto vfs_open_error;
	}

	err = check_file_create(ctx, file, dentry, hook_vfs_open);
	if (err < 0)
		goto vfs_open_error;

	return 0;

vfs_open_error:
	inc_error(hook_vfs_open, -err);
	return 0;
}
