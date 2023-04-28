#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/security_file_permission")
int BPF_KPROBE(security_file_permission, struct file *file, int mask)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	handle_generic_file_access(ctx, file, action, hook_security_file_permission);
	return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(security_file_permission_lsm, struct file *file, int mask)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_generic_file_access(ctx, file, action, hook_security_file_permission) == 1)
		return -EPERM;
	return 0;
}

SEC("fmod_ret/security_file_permission")
int BPF_PROG(security_file_permission_fmod, struct file *file, int mask, int ret)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_generic_file_access(ctx, file, action, hook_security_file_permission) == 1)
		return -EPERM;
	return 0;
}
