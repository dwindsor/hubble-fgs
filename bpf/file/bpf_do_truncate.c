#include "bpf_file.h"
#include "bpf_setattr.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/do_truncate/512")
int BPF_KPROBE(do_truncate_v512, struct user_namespace *mnt_userns, struct dentry *dentry, loff_t start, unsigned int time_attrs, struct file *filp)
{
	kprobe_do_truncate(ctx, dentry, start, hook_do_truncate);
	return 0;
}

SEC("kprobe/do_truncate/419")
int BPF_KPROBE(do_truncate_v419, struct dentry *dentry, loff_t start, unsigned int time_attrs, struct file *filp)
{
	kprobe_do_truncate(ctx, dentry, start, hook_do_truncate);
	return 0;
}
