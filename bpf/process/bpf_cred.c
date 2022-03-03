#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("kprobe/commit_creds")), used))
int event_commit_creds(struct pt_regs *ctx)
{
	size_t size = sizeof(struct msg_creds);
	struct execve_map_value *enter;
	const struct cred *cred;
	struct msg_creds c;
	__u32 pid;

	/* Safe to use map_lookup_event() here because we must have a
	 * valid tgid here because exec happened previously to populate
	 * it. This saves some overhead doing full process/parent lookup.
	 */
	pid = get_current_pid_tgid() >> 32;
	enter = execve_map_get(pid);
	if (!enter)
		return 0;
	if (!enter->key.ktime)
		return 0;

	c.common.op = MSG_OP_CREDS;
	c.common.flags = 0;
	c.common.pad[0] = 0;
	c.common.pad[1] = 0;
	c.common.size = size;
	c.common.ktime = ktime_get_ns();

	c.current.pid = pid;
	c.current.pad[0] = 0;
	c.current.pad[1] = 0;
	c.current.pad[2] = 0;
	c.current.pad[3] = 0;
	c.current.ktime = enter->key.ktime;

	probe_read(&cred, sizeof(cred), &ctx->di);
	probe_read(&c.caps.permitted, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&c.caps.effective, sizeof(__u64), _(&cred->cap_inheritable));
	probe_read(&c.caps.inheritable, sizeof(__u64), _(&cred->cap_permitted));

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &c, size);
	return 0;
}
