struct bpf_map_def __attribute__((section("maps"), used)) retprobe_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(unsigned long),
	.max_entries = 1024,
};

static inline __attribute__((always_inline))
unsigned long retprobe_map_get(__u64 tid)
{
	unsigned long *ptr;
	ptr = map_lookup_elem(&retprobe_map, &tid);
	if (!ptr)
		return 0;
	map_delete_elem(&retprobe_map, &tid);
	return *ptr;
}

static inline __attribute__((always_inline))
void retprobe_map_clear(__u64 tid)
{
	unsigned long *ptr = map_lookup_elem(&retprobe_map, &tid);

	if (ptr)
		map_delete_elem(&retprobe_map, &tid);
}

static inline __attribute__((always_inline))
void retprobe_map_set(__u64 tid, unsigned long val)
{
	map_update_elem(&retprobe_map, &tid, &val, BPF_ANY);
}

/* This returns the threadID we use in userspace to merge the kprobe
 * and kretprobe events into a single event. We used to use tid for
 * this, but for kprobe hooks outside kernel context, such as much
 * of the network stack below tcp and xfrm, this would not work
 * because get_current_pid_tgid returns an error when current is
 * nil -- nil is kernel context. So lets use the fp which is reliable
 * outside user ctx. The only caveat we will need to be aware of is
 * it is behind a kernel option CONFIG_FRAME_POINTER. In theory a
 * kernel omit frame-pointers, but we don't have any examples of this
 * so lets go for it.
 */
static inline __attribute__((always_inline))
__u64 retprobe_map_get_key(struct pt_regs *ctx)
{
	return (__u64)ctx->bp;
#if 0
	return get_current_pid_tgid()
#endif
}
