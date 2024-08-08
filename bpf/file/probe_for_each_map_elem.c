#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static long BPF_FUNC(for_each_map_elem, void *map, void *callback_fn, void *callback_ctx, __u64 flags);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4);
} test_probe_map SEC(".maps");

static int empty_callback(void *map, const void *key, void *value, void *ctx)
{
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_security_file_open, struct file *file)
{
	for_each_map_elem(&test_probe_map, &empty_callback, 0, 0);
	return 0;
}
