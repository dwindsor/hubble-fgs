#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_chmod")
int BPF_PROG(lsm_security_path_chmod, const struct path *path, umode_t mode, int ret)
{
	if (ret)
		return ret;

	return handle_dispatcher(ctx);
}
