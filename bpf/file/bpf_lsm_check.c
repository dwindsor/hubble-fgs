#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} tg_fnctl_map SEC(".maps");

SEC("lsm/file_fcntl")
int BPF_PROG(security_file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
{
	__u32 zero = 0;
	__u64 *calls = 0;

	calls = map_lookup_elem(&tg_fnctl_map, &zero);
	if (calls)
		__sync_fetch_and_add(calls, 1);

	return 0;
}
