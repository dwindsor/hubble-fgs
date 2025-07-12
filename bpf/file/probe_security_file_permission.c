#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "probe.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("fmod_ret/security_file_permission")
int BPF_PROG(fmod_security_file_permission, struct file *file, int mask)
{
	return probe_d_path(_(&file->f_path));
}