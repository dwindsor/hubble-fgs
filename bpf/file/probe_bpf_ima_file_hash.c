#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(ima_file_hash, struct file *file, void *dst, u32 size);

SEC("lsm.s/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm)
{
	__u64 data;
	ima_file_hash(bprm->file, &data, sizeof(__u64));
	return 0;
}
