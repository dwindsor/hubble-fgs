#include "bpf_file.h"
#include "bpf_setattr.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}
static inline gid_t __kgid_val(kgid_t gid)
{
	return gid.val;
}

/*
 * This function handles all setattr operations.
 * Returns:
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int security_inode_setattr(void *ctx, struct dentry *dentry, struct iattr *attr)
{
	unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);

	if (ia_valid & ATTR_MODE) { // chmod
		return kprobe_chmod_common(ctx, dentry, BPF_CORE_READ(attr, ia_mode), hook_security_inode_setattr);
	} else if ((ia_valid & ATTR_UID) || (ia_valid & ATTR_GID)) { // chown
		uid_t curr_user = BPF_CORE_READ(dentry, d_inode, i_uid).val;
		gid_t curr_group = BPF_CORE_READ(dentry, d_inode, i_gid).val;
		uid_t new_user = __kuid_val(BPF_CORE_READ(attr, ia_uid));
		gid_t new_group = __kgid_val(BPF_CORE_READ(attr, ia_gid));
		if (ia_valid & ATTR_UID) {
			curr_group = new_group = 0;
		} else if (ia_valid & ATTR_GID) {
			curr_user = new_user = 0;
		}
		return kprobe_chown_common(ctx, dentry, curr_user, new_user, curr_group, new_group, hook_security_inode_setattr);
	} else if (ia_valid & ATTR_SIZE) { // truncate
		return kprobe_do_truncate(ctx, dentry, BPF_CORE_READ(attr, ia_size), hook_security_inode_setattr);
	}
	return -1;
}

SEC("lsm/inode_setattr")
int BPF_PROG(security_inode_setattr_lsm, struct dentry *dentry, struct iattr *attr)
{
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (security_inode_setattr(ctx, dentry, attr) == 1)
		return -EPERM;
	return 0;
}

SEC("fmod_ret/security_inode_setattr")
int BPF_PROG(security_inode_setattr_fmod, struct dentry *dentry, struct iattr *attr, int ret)
{
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (security_inode_setattr(ctx, dentry, attr) == 1)
		return -EPERM;
	return 0;
}
