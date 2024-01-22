#include "bpf_file.h"
#include "check_file_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/finish_open")
int BPF_KPROBE(finish_open, struct file *file, struct dentry *dentry,
	       int (*open)(struct inode *, struct file *))
{
	int err;

	err = check_file_create(ctx, file, dentry, hook_finish_open);
	if (err < 0)
		inc_error(hook_finish_open, -err);

	return 0;
}
