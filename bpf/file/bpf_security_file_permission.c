#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/security_file_permission"), used)) int BPF_KPROBE(security_file_permission, struct file *file, int mask)
{
	int action = (mask == MAY_READ) ? (action_read) : (action_write);

	handle_generic_file_access(ctx, file, action, hook_security_file_permission);

	return 0;
}