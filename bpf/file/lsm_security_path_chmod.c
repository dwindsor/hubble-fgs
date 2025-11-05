#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "path_setattr.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static void f_chmod(struct msg_file_ops *msg, struct dentry *dentry, umode_t mode, uid_t uid, gid_t gid)
{
	msg->imode[OLDVAL] = BPF_CORE_READ(dentry, d_inode, i_mode); // current value
	msg->imode[NEWVAL] = mode; // new value
	msg->uid[OLDVAL] = msg->uid[NEWVAL] = 0xFFFFFFFF; // UINT32_MAX
	msg->gid[OLDVAL] = msg->gid[NEWVAL] = 0xFFFFFFFF; // UINT32_MAX
}

SEC("lsm/path_chmod")
int BPF_PROG(lsm_security_path_chmod, const struct path *path, umode_t mode)
{
	int err;

	err = path_setattr(ctx, path, action_chattr, hook_security_path_chmod, mode, 0, 0, f_chmod);
	if (err < 0) {
		inc_error(hook_security_path_chmod, -err);
		return 0;
	}

	return handle_tail_call(ctx, handle_enforcement(err));
}
