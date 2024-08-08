#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) __u32 path_setattr(void *ctx, const struct path *path, __u32 action, __u32 hook, umode_t mode, uid_t uid, gid_t gid, void (*set_attr)(struct msg_file_ops *, struct dentry *, umode_t, uid_t, gid_t))
{
	__u32 s_magic, operation, rule_id;
	struct msg_file_ops *msg;
	struct dentry *dentry;
	int err;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	dentry = BPF_CORE_READ(path, dentry);
	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	s_magic = BPF_CORE_READ(path, dentry, d_inode, i_sb, s_magic);
	rule_id = run_matcher(s_magic);
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(msg, (struct path *)path);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action, 0, 0, msg->path.str, msg->path.size);
	if (!(operation & FILE_OP_POST))
		return 0;

	set_attr(msg, dentry, mode, uid, gid);

	complete_msg(msg, action, hook, operation, rule_id, 0);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

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

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}

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

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}

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

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}