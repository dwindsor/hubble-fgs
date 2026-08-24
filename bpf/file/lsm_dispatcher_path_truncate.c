#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_truncate")
int BPF_PROG(lsm_security_path_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;

	return handle_dispatcher(ctx);
}
