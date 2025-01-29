#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/mmap_file")
int BPF_PROG(lsm_security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
	return handle_dispatcher(ctx);
}
