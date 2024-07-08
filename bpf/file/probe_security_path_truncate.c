#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

SEC("lsm/path_truncate")
int BPF_PROG(lsm_security_path_truncate, const struct path *path)
{
	char buf[32];
	d_path((struct path *)path, buf, sizeof(buf));
	return 0;
}