#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "probe.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	return probe_d_path(_(&file->f_path));
}