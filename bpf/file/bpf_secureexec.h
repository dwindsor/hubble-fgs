#ifndef __BPF_SECUREEXEC_H__
#define __BPF_SECUREEXEC_H__

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

// copied from https://github.com/cilium/tetragon/blob/b8f2a4fe9b6f74018dd2302f2fe9098818b0742a/bpf/process/bpf_execve_bprm_commit_creds.c
FUNC_LOCAL void generate_secureexec(struct msg_file_ops *msg, struct linux_binprm *bprm)
{
	__u32 ruid, euid, uid, egid, gid, sec = 0;
	__u64 permitted, new_permitted, new_ambient = 0;
	struct task_struct *task;

	/* If no flags to clear then this is not a privileged execution */
	if (BPF_CORE_READ_INTO(&sec, bprm, per_clear) != 0 || sec == 0)
		return;

	/* Check if this is a setuid or setgid */
	euid = BPF_CORE_READ(bprm, cred, euid.val);
	egid = BPF_CORE_READ(bprm, cred, egid.val);

	task = (struct task_struct *)get_current_task();
	uid = BPF_CORE_READ(task, cred, uid.val);
	gid = BPF_CORE_READ(task, cred, gid.val);

	msg->uid[NEWVAL] = euid;
	msg->uid[OLDVAL] = uid;
	msg->gid[NEWVAL] = egid;
	msg->gid[OLDVAL] = gid;

	/* Is setuid? */
	if (euid != uid) {
		msg->secureexec |= EXEC_SETUID;
		/* If euid is being changed to root? */
		ruid = BPF_CORE_READ(bprm, cred, uid.val);
		if (!__is_uid_global_root(ruid) && __is_uid_global_root(euid))
			/* If we executed from a non root and became global effective root
			 * then set the EXEC_FS_SETUID to indicate that there was a privilege
			 * elevation through binary suid root.
			 * Now it is possible that the root 0 does not have capabilities
			 * meaning it is running with SECURE_NOROOT Sec bit set, but we still
			 * handle it as privileged change since running with uid root allows
			 * to access files, ptrace root binaries, etc. From Tetragon euid==0
			 * is still raising privileges.
			 *
			 * Note: there is the case of a uid being in a user namespace
			 *    and it is mapped to uid 0 root inside that namespace that we do
			 *    not detect now, since we do not do user ids translation into
			 *    user namespaces. For such case we may not report if the binary
			 *    gained privileges through setuid. To be fixed in the future.
			 */
			msg->secureexec |= EXEC_SETUID_ROOT;
	}
	/* Is setgid? */
	if (egid != gid) {
		msg->secureexec |= EXEC_SETGID;
		/* Is egid is being changed to real root? */
		gid = BPF_CORE_READ(bprm, cred, gid.val);
		if (!__is_uid_global_root(gid) && __is_uid_global_root(egid))
			/* If we executed a setgid to root binary then this is a
			 * privilege elevation since it can now access root files, etc
			 */
			msg->secureexec |= EXEC_SETGID_ROOT;
	}

	/* Ensure that ambient capabilities are not set since they clash with:
	 *   setuid/setgid on the binary.
	 *   file capabilities on the binary.
	 *
	 * This is an extra guard. Since if the new ambient capabilities are set then
	 * there is no way the binary could provide extra capabilities, they cancel
	 * each other.
	 */
	BPF_CORE_READ_INTO(&new_ambient, bprm, cred, cap_ambient);
	if (new_ambient)
		return;

	/* Did we gain new capabilities through execve?
	 *
	 * To determin if we gained new capabilities we compare the current permitted
	 *  set with the new set. This can happen if:
	 *   (1) The setuid of binary is the _mapped_ root id in current or parent owning namespace.
	 *       This is already handled above in the setuid code path.
	 *   (2) The file capabilities are set on the binary. If the setuid bit is not set
	 *       then the gained capabilities are from file capabilities execution.
	 */
	BPF_CORE_READ_INTO(&permitted, task, cred, cap_permitted);
	BPF_CORE_READ_INTO(&new_permitted, bprm, cred, cap_permitted);
	if (__cap_gained(new_permitted, permitted) && euid == uid) {
		/* If the setuid bit is not set then this is probably a file cap execution. */
		msg->secureexec |= EXEC_FILE_CAPS;
	}
}

#endif /* __BPF_SECUREEXEC_H__ */
