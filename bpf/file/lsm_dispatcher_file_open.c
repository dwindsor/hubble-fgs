#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	return handle_dispatcher(ctx);
}
