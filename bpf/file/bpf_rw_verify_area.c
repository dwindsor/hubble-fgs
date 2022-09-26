#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/rw_verify_area"), used)) int
BPF_KPROBE(rw_verify_area, int read_write, struct file *file,
	   const loff_t *ppos, size_t count)
{
	__s64 offset;
	probe_read(&offset, sizeof(offset), ppos);

	if (read_write == READ)
		return handle_generic_file_read(ctx, file, hook_rw_verify_area,
						offset, count);
	else // (type == WRITE)
		return handle_generic_file_write(ctx, file, hook_rw_verify_area,
						 offset, count);
}
