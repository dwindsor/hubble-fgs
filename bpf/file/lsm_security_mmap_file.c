#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/mmap_file")
int BPF_PROG(lsm_security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
	int action = 0, file_backed = 0;
	int err;

	file_backed = (flags & MAP_SHARED) || (flags & MAP_PRIVATE) || (flags & MAP_SHARED_VALIDATE);
	if (!file_backed)
		return 0;

	action = 0;
	if (prot & PROT_READ)
		action = action_read;
	if ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE)) // having a write operation with MAP_PRIVATE will never reach the file
		action = action_write;
	if (!action)
		return 0;

	err = path_generic_file_access(ctx, file, action, hook_security_mmap_file);
	if (err < 0) {
		inc_error(hook_security_mmap_file, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
