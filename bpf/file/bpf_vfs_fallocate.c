#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/vfs_fallocate"), used)) int
BPF_KPROBE(vfs_fallocate, struct file *file, int mode, loff_t offset,
	   loff_t len)
{
	return handle_generic_file_write(ctx, file, hook_vfs_fallocate, offset,
					 len);
}
