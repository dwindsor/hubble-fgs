#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

struct bpf_map_def __attribute__((section("maps"), used)) udp_retprobe_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct udp_info_key),
	.max_entries = 1024,
};

static inline __attribute__((always_inline))
struct udp_info_key *udp4_get_key(struct pt_regs *ctx)
{
	struct sock *sk = (void *)ctx->di;
	struct inet_sock *inet = (void *)sk;
	struct msghdr *msg = (void *)ctx->si;
	struct sockaddr_in *in;
	int namelen;

	struct udp_info_key *key;
	int zero = 0;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	probe_read(&in, sizeof(void*), _(&(msg->msg_name)));
	probe_read(&namelen, sizeof(int), _(&(msg->msg_namelen)));
	if (in && namelen >= sizeof(*in)) {
		probe_read(&key->daddr, sizeof(u32), _(&(in->sin_addr.s_addr)));
		probe_read(&key->dport, sizeof(u16), _(&(in->sin_port)));
	} else {
		probe_read(&key->daddr, sizeof(u32), _(&(sk->__sk_common.skc_daddr)));
		probe_read(&key->dport, sizeof(u16), _(&(sk->__sk_common.skc_dport)));
	}
	probe_read(&key->saddr, sizeof(u32), _(&(inet->inet_saddr)));
	probe_read(&key->sport, sizeof(u16), _(&(inet->inet_sport)));
	key->padding = 0;
	return key;
}

__attribute__((section(("kprobe/udp_sendmsg")), used))
int udp4_send(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid();
	struct udp_info_value *value;
	struct udp_info_key *key;

	key = udp4_get_key(ctx);
	if (!key)
		return 0;

	value = map_lookup_elem(&udp_map, key);
	if (!value) {
		struct execve_map_value *process;
		int zero = 0;
		bool walker;
		u32 ppid;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		udp_info_reset(value, 0);
		process = event_find_curr(&ppid, 0, &walker);
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		}
		map_update_elem(&udp_map, key, value, 0);
	} else {
		update_tx_value(value, 0);
	}
	map_update_elem(&udp_retprobe_map, &pid, key, 0);
	return 0;
}

__attribute__((section(("kretprobe/udp_sendmsg")), used))
int udp4_sendret(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid();
	struct udp_info_key *key;
	int ret;

	ret = ctx->ax;
	if (ret < 0)
		return 0;

	key = map_lookup_elem(&udp_retprobe_map, &pid);
	if (key) {
		struct udp_info_value *value = map_lookup_elem(&udp_map, key);

		if (value) {
			value->tx_bytes += ret;
			value->segs_out++;
			emit_udp_connect_event(ctx, key, value);
		}
		map_delete_elem(&udp_retprobe_map, &pid);
	}
	return 0;
}
