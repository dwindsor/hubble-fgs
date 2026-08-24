#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_link")
int BPF_PROG(lsm_security_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;

	return handle_dispatcher(ctx);
}
