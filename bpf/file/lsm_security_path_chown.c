#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"
#include "path_setattr.h"
#include "dispatcher.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static void f_chown(struct msg_file_ops *msg, struct dentry *dentry, umode_t mode, uid_t uid, gid_t gid)
{
	msg->uid[OLDVAL] = __kuid_val(BPF_CORE_READ(dentry, d_inode, i_uid));
	msg->gid[OLDVAL] = __kgid_val(BPF_CORE_READ(dentry, d_inode, i_gid));
	msg->uid[NEWVAL] = uid;
	msg->gid[NEWVAL] = gid;
	msg->imode[OLDVAL] = msg->imode[NEWVAL] = 0xFFFF; // UINT16_MAX
}

SEC("lsm/path_chown")
int BPF_PROG(lsm_security_path_chown, const struct path *path, uid_t uid, gid_t gid)
{
	int err;

	err = path_setattr(ctx, path, action_chattr, hook_security_path_chown, 0, uid, gid, f_chown);
	if (err < 0) {
		inc_error(hook_security_path_chown, -err);
		return 0;
	}

	return handle_tail_call(ctx, handle_enforcement(err));
}
