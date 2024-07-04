#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("fmod_ret/security_file_permission")
int BPF_PROG(fmod_security_file_permission, struct file *file, int mask)
{
	int err, action = (mask == MAY_READ) ? (action_read) : (action_write);

	// this is a directory read operation (i.e. action_readdir)
	if (S_ISDIR(BPF_CORE_READ(file, f_inode, i_mode)))
		action = action_readdir;

	err = path_generic_file_access(ctx, file, action, hook_security_file_permission);
	if (err < 0) {
		inc_error(hook_security_file_permission, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
