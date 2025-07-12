#ifndef __PROBE_H__
#define __PROBE_H__

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

struct __attribute__((aligned(8))) full_path {
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct full_path);
	__uint(max_entries, 1);
} filename_heap_map SEC(".maps");

static inline __attribute__((always_inline)) int probe_d_path(struct path *path)
{
	struct full_path *buf = 0;
	int zero = 0;

	buf = map_lookup_elem(&filename_heap_map, &zero);
	if (!buf)
		return 0;

	d_path(path, buf->path, sizeof(buf->path));

	return 0;
}

#endif /* __PROBE_H__ */