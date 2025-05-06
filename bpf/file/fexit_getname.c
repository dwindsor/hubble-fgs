#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"
#include "getname.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("fexit/getname")
int BPF_PROG(getname, const char *filename, struct filename *f)
{
	return handle_getname(filename, f);
}