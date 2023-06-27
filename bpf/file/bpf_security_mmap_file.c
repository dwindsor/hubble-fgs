#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/mmap_file")
int BPF_PROG(security_mmap_file_lsm, struct file *file, unsigned long prot, unsigned long flags)
{
	int action = 0, file_backed = 0;

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

	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_generic_file_access(ctx, file, action, hook_security_mmap_file) == 1)
		return -EPERM;
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_mmap_file")
int BPF_PROG(security_mmap_file_fmod, struct file *file, unsigned long prot, unsigned long flags, int ret)
{
	int action = 0, file_backed = 0;

	if (ret != 0)
		return ret;

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

	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_generic_file_access(ctx, file, action, hook_security_mmap_file) == 1)
		return -EPERM;
	return 0;
}
#endif
