#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

SEC("fmod_ret/security_file_permission")
int BPF_PROG(fmod_security_file_permission, struct file *file, int mask)
{
	char buf[32];
	d_path(_(&file->f_path), buf, sizeof(buf));
	return 0;
}