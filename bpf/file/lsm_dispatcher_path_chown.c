#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_chown")
int BPF_PROG(lsm_security_path_chown, const struct path *path, uid_t uid, gid_t gid)
{
	return handle_dispatcher(ctx);
}
