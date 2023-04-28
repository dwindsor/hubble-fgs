#include "bpf_file.h"
#include "bpf_setattr.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/chown_common")
int BPF_KPROBE(chown_common, const struct path *path, uid_t user, gid_t group)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;

	uid_t curr_user = BPF_CORE_READ(dentry, d_inode, i_uid).val;
	gid_t curr_group = BPF_CORE_READ(dentry, d_inode, i_gid).val;
	kprobe_chown_common(ctx, dentry, curr_user, user, curr_group, group, hook_chown_common);

	return 0;
}
