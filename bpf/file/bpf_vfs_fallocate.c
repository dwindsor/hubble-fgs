#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/vfs_fallocate"), used)) int
BPF_KPROBE(vfs_fallocate, struct file *file, int mode, loff_t offset,
	   loff_t len)
{
	return handle_generic_file_access(ctx, file, action_write, hook_vfs_fallocate);
}
