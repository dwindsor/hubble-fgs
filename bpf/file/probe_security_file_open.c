#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	char buf[32];
	d_path(_(&file->f_path), buf, sizeof(buf));
	return 0;
}