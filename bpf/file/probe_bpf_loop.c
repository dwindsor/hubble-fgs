
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static int empty_callback(__u32 index, void *data)
{
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	loop(4, empty_callback, 0, 0);
	return 0;
}