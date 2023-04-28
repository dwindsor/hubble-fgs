#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/vfs_fallocate")
int BPF_KPROBE(vfs_fallocate, struct file *file, int mode, loff_t offset, loff_t len)
{
	handle_generic_file_access(ctx, file, action_write, hook_vfs_fallocate);
	return 0;
}
