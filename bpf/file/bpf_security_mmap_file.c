#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/mmap_file")
int BPF_PROG(security_mmap_file_lsm, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret)
{
	int action = 0, file_backed = 0;
	int err;

	if (ret)
		return ret;
	if (!file)
		return 0;

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

	err = handle_generic_file_access(ctx, file, action, hook_security_mmap_file);
	if (err < 0) {
		inc_error(hook_security_mmap_file, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_mmap_file")
int BPF_PROG(security_mmap_file_fmod, struct file *file, unsigned long prot, unsigned long flags, int ret)
{
	int action = 0, file_backed = 0;
	int err;

	if (ret != 0)
		return ret;
	if (!file)
		return 0;

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

	err = handle_generic_file_access(ctx, file, action, hook_security_mmap_file);
	if (err < 0) {
		inc_error(hook_security_mmap_file, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif
