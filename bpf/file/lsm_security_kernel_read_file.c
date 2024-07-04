#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_security_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	int err;

	err = path_generic_file_access(ctx, file, action_read, hook_security_kernel_read_file);
	if (err < 0) {
		inc_error(hook_security_kernel_read_file, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
