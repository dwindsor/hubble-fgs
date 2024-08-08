#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "bpf_event.h"
#include "bpf_task.h"

#include "file.h"
#include "bpf_glob.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define MAX_PATH_SZIE 256

struct str {
	char path[MAX_PATH_SZIE];
	__u32 len;
	__u32 pad;
	__u64 res;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct str);
	__uint(max_entries, 1);
} tg_string_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct glob_state);
	__uint(max_entries, 256); // should be enough for all tests
} tg_pattern_map SEC(".maps");

SEC("lsm/file_fcntl")
int BPF_PROG(security_file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct str *s;
	u32 zero = 0;

	s = map_lookup_elem(&tg_string_map, &zero);
	if (!s)
		return 0;

	s->res = check_pattern(&tg_pattern_map, s->path, s->len);

	return 0;
}
