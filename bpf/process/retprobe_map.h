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
void retprobe_map_set(__u64 tid, unsigned long val)
{
	map_update_elem(&retprobe_map, &tid, &val, BPF_ANY);
}
