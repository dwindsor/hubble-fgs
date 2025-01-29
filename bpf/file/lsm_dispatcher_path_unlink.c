#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_unlink")
int BPF_PROG(lsm_security_path_unlink, const struct path *dir, struct dentry *dentry)
{
	return handle_dispatcher(ctx);
}
