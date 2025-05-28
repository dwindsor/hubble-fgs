#ifndef __GETNAME_H___
#define __GETNAME_H___

#if defined __TARGET_ARCH_x86
#define ARCH "x64"
#elif defined __TARGET_ARCH_arm64
#define ARCH "arm64"
#else
#pragma message("unknown arch")
#endif

#define FEXIT(a, b) "fexit/__" a "_" b

struct kpath_val {
	char str[MAX_FILEPATH_SIZE];
	__u32 size;
	__u32 flags;
	__s64 refcnt;
};

struct kpath_key {
	__u64 ptr;
	__u64 pid_tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct kpath_val);
	__uint(max_entries, 1);
} kpath_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct kpath_key);
	__type(value, struct kpath_val);
} open_user_to_kernel_path SEC(".maps");

static inline __attribute__((always_inline)) int handle_getname(const char *filename, struct filename *f)
{
	struct kpath_key map_key = {
		.ptr = (__u64)filename,
		.pid_tgid = get_current_pid_tgid(),
	};
	struct kpath_val *kpath;
	int zero = 0;
	long ret;

	if (!f)
		return 0;

	// first check if we can find that in the map
	kpath = map_lookup_elem(&open_user_to_kernel_path, &map_key);
	if (kpath) {
		ret = probe_read_kernel_str(kpath->str, MAX_FILEPATH_SIZE, BPF_CORE_READ(f, name));
		kpath->size = (ret > 0) ? (ret - 1) : (0);
		kpath->flags = 0;
		__sync_fetch_and_add(&kpath->refcnt, 1);
	} else {
		kpath = map_lookup_elem(&kpath_heap, &zero);
		if (!kpath)
			return 0;

		ret = probe_read_kernel_str(kpath->str, MAX_FILEPATH_SIZE, BPF_CORE_READ(f, name));
		kpath->size = (ret > 0) ? (ret - 1) : (0);
		kpath->flags = 0;
		kpath->refcnt = 1;

		map_update_elem(&open_user_to_kernel_path, &map_key, kpath, 0);
	}

	return 0;
}

#endif /* __GETNAME_H___ */
