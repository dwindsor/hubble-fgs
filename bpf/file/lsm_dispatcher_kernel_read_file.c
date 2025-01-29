#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_security_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	return handle_dispatcher(ctx);
}
