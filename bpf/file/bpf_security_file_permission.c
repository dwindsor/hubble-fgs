#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/security_file_permission")
int BPF_KPROBE(security_file_permission, struct file *file, int mask)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	int err;

	err = handle_generic_file_access(ctx, file, action, hook_security_file_permission);
	if (err < 0)
		inc_error(hook_security_file_permission, -err);

	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/file_permission")
int BPF_PROG(security_file_permission_lsm, struct file *file, int mask, int ret)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	int err;

	if (ret)
		return ret;

	err = handle_generic_file_access(ctx, file, action, hook_security_file_permission);
	if (err < 0) {
		inc_error(hook_security_file_permission, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_file_permission")
int BPF_PROG(security_file_permission_fmod, struct file *file, int mask, int ret)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	int err;

	if (ret != 0)
		return ret;

	err = handle_generic_file_access(ctx, file, action, hook_security_file_permission);
	if (err < 0) {
		inc_error(hook_security_file_permission, -err);
		return 0;
	}

	return handle_enforcement(err);
}
#endif
