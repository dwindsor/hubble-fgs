#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "probe.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_security_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	return probe_d_path(_(&file->f_path));
}