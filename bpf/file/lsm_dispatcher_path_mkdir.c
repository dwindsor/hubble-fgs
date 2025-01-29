#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_mkdir")
int BPF_PROG(lsm_security_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return handle_dispatcher(ctx);
}
