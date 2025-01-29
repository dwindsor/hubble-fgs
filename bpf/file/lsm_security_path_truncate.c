#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "path_setattr.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static void f_truncate(struct msg_file_ops *msg, struct dentry *dentry, umode_t mode, uid_t uid, gid_t gid) {}

SEC("lsm/path_truncate")
int BPF_PROG(lsm_security_path_truncate, const struct path *path)
{
	int err;

	err = path_setattr(ctx, path, action_write, hook_security_path_truncate, 0, 0, 0, f_truncate);
	if (err < 0) {
		inc_error(hook_security_path_truncate, -err);
		return 0;
	}

	return handle_tail_call(ctx, err & FILE_OP_BLOCK ? -EPERM : 0);
}