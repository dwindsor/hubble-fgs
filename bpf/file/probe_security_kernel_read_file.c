#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_security_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	char buf[32];
	d_path(_(&file->f_path), buf, sizeof(buf));
	return 0;
}