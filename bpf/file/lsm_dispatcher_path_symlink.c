#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_symlink")
int BPF_PROG(lsm_security_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	return handle_dispatcher(ctx);
}
