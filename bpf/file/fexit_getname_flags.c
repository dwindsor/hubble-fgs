#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"
#include "getname.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("fexit/getname_flags")
int BPF_PROG(getname_flags, const char *filename, int flags, struct filename *f)
{
	return handle_getname(filename, f);
}