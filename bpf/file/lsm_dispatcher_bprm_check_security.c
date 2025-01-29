#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	return handle_dispatcher(ctx);
}
