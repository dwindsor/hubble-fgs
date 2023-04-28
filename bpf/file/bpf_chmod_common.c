#include "bpf_file.h"
#include "bpf_setattr.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/chmod_common")
int BPF_KPROBE(chmod_common, const struct path *path, umode_t mode)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;

	kprobe_chmod_common(ctx, dentry, mode, hook_chmod_common);
	return 0;
}
