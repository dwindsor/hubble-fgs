#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "probe.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("lsm/path_truncate")
int BPF_PROG(lsm_security_path_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;

	return probe_d_path((struct path *)path);
}
