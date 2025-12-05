#define HAS_POLICY_STATS
#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "bpf_event.h"
#include "bpf_task.h"

#include "file.h"
#include "iso_msg_types.h"
#include "bpf_process_event.h"
#include "types/operations.h"
#include "retprobe_map.h"
#include "string_maps.h"
#include "types/basic.h"
#include "process/policy_filter.h"
#include "bpf_overlay.h"
#include "bpf_ktime.h"

#ifdef __ENABLE_GLOB_SUPPORT
#include "bpf_glob.h"
#endif

#include "policy_conf.h"
#include "policy_stats.h"

#define FILTER_NOTFOUND -1
#define FILTER_IGNORE	0
#define FILTER_MATCH	1
#define FILTER_MONITOR	2

/* generic data direction definitions */
#define READ  0
#define WRITE 1

#define MAY_WRITE 0x00000002
#define MAY_READ  0x00000004

#define PROT_READ  0x1 /* page can be read */
#define PROT_WRITE 0x2 /* page can be written */

#define MAP_SHARED	    0x01 /* Share changes */
#define MAP_PRIVATE	    0x02 /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */

#define FAULT_FLAG_WRITE   0x01
#define FAULT_FLAG_MKWRITE 0x02

#define VM_READ	  0x00000001
#define VM_WRITE  0x00000002
#define VM_SHARED 0x00000008

#define FMODE_CREATED 0x100000

#define PAGE_SIZE 4096

#if defined(__ENABLE_GLOB_SUPPORT)
#define MAX_FIM_SELECTORS 128
#elif defined(__LARGE_BPF_PROG)
#define MAX_FIM_SELECTORS 6
#else
#define MAX_FIM_SELECTORS 4
#endif

// should match PatternMapSize in client_file.go
#define MAX_FILE_PATTERNS 32

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev)    ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int)((dev) & MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

#define S_IFMT	 00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG	 0100000
#define S_IFBLK	 0060000
#define S_IFDIR	 0040000
#define S_IFCHR	 0020000
#define S_IFIFO	 0010000

#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

// rename flags
#define MOVE_INSIDE	(1 << 0)
#define MOVE_OUTSIDE	(1 << 1)
#define MOVE_INTERNALLY (1 << 2)
#define SRC_REG_FILE	(1 << 3)
#define SRC_DIRECTORY	(1 << 4)
#define SRC_CHAR_DEV	(1 << 5)
#define SRC_BLOCK_DEV	(1 << 6)
#define SRC_NAMED_PIPE	(1 << 7)
#define SRC_SYMLINK	(1 << 8)
#define SRC_SOCKET	(1 << 9)
#define SRC_INVALID	(1 << 10)
#define DST_NOT_EXISTS	(1 << 11)
#define DST_REG_FILE	(1 << 12)
#define DST_DIRECTORY	(1 << 13)
#define DST_CHAR_DEV	(1 << 14)
#define DST_BLOCK_DEV	(1 << 15)
#define DST_NAMED_PIPE	(1 << 16)
#define DST_SYMLINK	(1 << 17)
#define DST_SOCKET	(1 << 18)
#define DST_INVALID	(1 << 19)

/*
 * Attribute flags.  These should be or-ed together to figure out what
 * has been changed!
 */
#define ATTR_MODE      (1 << 0)
#define ATTR_UID       (1 << 1)
#define ATTR_GID       (1 << 2)
#define ATTR_SIZE      (1 << 3)
#define ATTR_ATIME     (1 << 4)
#define ATTR_MTIME     (1 << 5)
#define ATTR_CTIME     (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE     (1 << 9) /* Not a change, but a change it */
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE      (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN      (1 << 15) /* Truncating from open(O_TRUNC) */
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_TOUCH     (1 << 17)

#define NS_FILTER_ALL	 0
#define NS_FILTER_HOST	 1
#define NS_FILTER_NOHOST 2

#define FS_CREATE 0x00000100 /* Subfile was created */

#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define TMPFS_MAGIC	      0x01021994
#define HUGETLBFS_MAGIC	      0x958458f6

#define O_ACCMODE 00000003UL

#define OLDVAL 0
#define NEWVAL 1

static inline uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}

static inline gid_t __kgid_val(kgid_t gid)
{
	return gid.val;
}

static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);
static long BPF_FUNC(probe_read_kernel_str, void *dst, u32 size, const void *unsafe_ptr);
static long BPF_FUNC(for_each_map_elem, void *map, void *callback_fn, void *callback_ctx, __u64 flags);

#ifdef __LARGE_BPF_PROG
// re-write this in user-space to enable bpf_d_path helper
// This is because https://github.com/torvalds/linux/commit/b13cddf633562b9b2c34fd63471d377019704ebe
// which allows bpf_d_path helper into security_path_* functions.
volatile const __u32 USE_BPF_D_PATH_HELPER = 0;

volatile const __u32 HAS_MATCH_BINARIES = 1;
volatile const __u32 HAS_MATCH_OPERATIONS = 1;
volatile const __u32 HAS_MATCH_DIGESTS = 1;
volatile const __u32 HAS_MATCH_NAMESPACES = 1;
volatile const __u32 HAS_MATCH_CAPABILITIES = 1;
volatile const __u32 HAS_MATCH_RENAME_SRC_TYPE = 1;
volatile const __u32 HAS_MATCH_OPEN_FLAGS = 1;
volatile const __u32 HAS_MATCH_FILENAME = 1;
volatile const __u32 HAS_MATCH_EXEC_ATTRIBUTES = 1;
volatile const __u32 HAS_MATCH_OPENRAW_RESULT = 1;
volatile const __u32 HAS_MATCH_UID_GID = 1;
volatile const __u32 HAS_MATCH_PROCESS_DURATION = 1;
volatile const __u32 HAS_MATCH_BINARY_PROPERTIES = 1;

#define INVALID_MATCHER	   0
#define MATCH_ALL	   1
#define FS_TYPE_MATCHER	   2
#define INODE_TYPE_MATCHER 3

volatile const __u32 PATH_BASED_MATCHER = 0;
#endif /* __LARGE_BPF_PROG */

#define INVALID_RULE_ID	   0xffffffff // UINT32_MAX
#define INVALID_SECUREEXEC 0xffffffff // UINT32_MAX

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, struct vfs_mk_info);
	__uint(max_entries, 1024);
} mk_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct vfs_mk_info);
	__uint(max_entries, 1);
} vfs_mk_info_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct inode_pair);
	__type(value, int);
	__uint(max_entries, 4096);
} fsnotify_created_files_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, struct vfs_rename_info);
	__uint(max_entries, 1024);
} rename_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, __u64);
	__uint(max_entries, 1024);
} spr_retprobe_map SEC(".maps"); // security_path_rename retprobe map

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, __u64);
	__uint(max_entries, 1024);
} vr_retprobe_map SEC(".maps"); // vfs_rename retprobe map

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct vfs_rename_info);
	__uint(max_entries, 1);
} vfs_rename_info_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_file_rename_ops);
	__uint(max_entries, 1);
} file_rename_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_file_ops);
	__uint(max_entries, 1);
} file_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_ns);
	__uint(max_entries, 1);
} file_msg_ns_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_capabilities);
	__uint(max_entries, 1);
} file_msg_caps_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct pattern_val);
	__uint(max_entries, MAX_FILE_PATTERNS);
} patterns_map_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct full_path);
	__type(value, __u32);
	__uint(max_entries, 1); /* the user will setup this */
} exact_match_map_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1); /* the user will setup this */
} file_system_type_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1); /* the user will setup this */
} inode_type_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct lpm_val);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_trie_map_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct lpm_key);
	__uint(max_entries, 1);
} lpm_trie_heap_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct inode_key);
	__type(value, struct inode_val);
	__uint(max_entries, 1); /* the user will setup this */
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hash_map_inode_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s64);
} hash_map_inode_alloc_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct inode_val);
	__uint(max_entries, 1);
} file_val_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct string_prefix_lpm_trie);
	__uint(max_entries, 1);
} file_prefix_lpm_heap SEC(".maps");

struct exec_key {
	__u64 pid_tgid;
	__u64 bprm_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct exec_key);
	__type(value, struct msg_file_ops);
	__uint(max_entries, 128);
} exec_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u32);
			__type(value, __u32);
		});
} file_ops_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, struct digest_key);
			__type(value, __u32);
		});
} file_digests_maps SEC(".maps");

struct pattern_key {
	__u32 sel_idx;
	__u32 pattern_idx;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS); // max number of selectors -- to be set from the user-space
	__type(key, struct pattern_key); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_ARRAY);
			__type(key, __u32);
			__type(value, struct glob_state);
			__uint(max_entries, 1);
		});
} glob_patterns_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, struct file_sel_caps);
} file_capabilities_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, struct file_sel_rename);
} file_rename_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); /* the user will setup this */
	__type(key, __u32); /* selector id */
	__type(value, __u32); /* match_filename_* */
} filename_ops_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS); // max number of selectors -- to be set from the user-space
	__type(key, __u32); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(key_size, MAX_FILEPATH_SIZE * sizeof(char));
			__type(value, __u32);
			__uint(max_entries, 1); // to be set from the user-space
		});
} filename_path_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct full_path);
	__uint(max_entries, 1);
} filename_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS); // max number of selectors -- to be set from the user-space
	__type(key, __u32); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__type(key, struct digest_key);
			__type(value, __u32);
			__uint(max_entries, 1); // to be set from the user-space
		});
} filename_digest_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct digest_key);
	__uint(max_entries, 1);
} digest_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct exec_key);
	__type(value, struct msg_file_ops);
	__uint(max_entries, 128);
} exec_cred_map SEC(".maps");

#define EXEC_ATTR_MEMFD_IDX 0
#define EXEC_ATTR_UPPER_IDX 1

union exec_flags {
	__u32 d32;
	__u8 d8[sizeof(__u32) / sizeof(__u8)];
};

#define MATCH_EXEC_ATTR_FALSE 0
#define MATCH_EXEC_ATTR_TRUE  1
#define MATCH_EXEC_ATTR_ANY   2

struct exec_attr {
	__u32 is_exe_upper_layer; // MATCH_EXEC_ATTR_*
	__u32 is_exe_from_memfd; // MATCH_EXEC_ATTR_*
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* selector id */
	__type(value, struct exec_attr);
	__uint(max_entries, MAX_FIM_SELECTORS); // max number of selectors -- to be set from the user-space
} exec_attributes_map SEC(".maps");

#define MAX_SELECTOR_OPEN_FLAGS 8

// Need to declare the value of the inner map here otherwise we get the
// following error:
// time="2024-06-11T07:24:35Z" level=fatal msg="Failed to start tetragon"
// error="failed to get sensors from parser policy: sensor fim_sensor_1
// from collection file-monitoring failed to load: tetragon, aborting
// could not load sensor BPF maps: failed to open collection
// 'bpf/objs/bpf_vfs_fallocate.o': file bpf/objs/bpf_vfs_fallocate.o:
// load BTF maps: map file_open_flags_map: can't parse BTF map definition
// of inner map: can't get size of BTF value: type *btf.Fwd: type is
// unsized"
__attribute__((unused)) struct onflags _onflags;
__attribute__((unused)) struct glob_state _glob_state;

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_ARRAY);
			__uint(max_entries, 1);
			__type(key, __u32);
			__type(value, struct onflags);
		});
} file_open_flags_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, struct file_sel_namespaces);
} file_namespaces_map SEC(".maps");

struct file_actions_val {
	__u32 val;
	__u32 msg_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, struct file_actions_val);
} file_actions_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_config_map_value);
} file_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct io_uring_op_key);
	__type(value, struct io_uring_op_val);
	__uint(max_entries, 1024);
} io_uring_map SEC(".maps");

struct io_uring_info {
	struct io_kiocb *req;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, struct io_uring_info);
	__uint(max_entries, 1024);
} io_uring_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct file_errors);
	__uint(max_entries, 1);
} file_errors_map SEC(".maps");

struct sel_path {
	char *path;
	__u32 len;
};

struct sel_args {
	__u32 action;
	__u32 flags;
	__s32 retval;
	__u32 secureexec;
};

#define SEL_OPENRAW_SUCCESS 0
#define SEL_OPENRAW_FAILURE 1

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32); /* SEL_OPENRAW_* */
	__uint(max_entries, 1); /* the user will setup this */
} file_openraw_result_map SEC(".maps");

struct sel_uidgid {
	__u32 uid_op;
	__u32 uid_val;
	__u32 gid_op;
	__u32 gid_val;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct sel_uidgid); /* SEL_UIDGID_* */
	__uint(max_entries, 1); /* the user will setup this */
} file_uidgid_map SEC(".maps");

struct sel_binprop {
	__u32 secureexec_op;
	__u32 secureexec_val;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct sel_binprop);
	__uint(max_entries, 1); /* the user will setup this */
} file_binprop_map SEC(".maps");

struct sel_proc_dur {
	__u32 op;
	__u32 pad;
	__u64 val;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct sel_proc_dur);
	__uint(max_entries, 1); /* the user will setup this */
} file_proc_dur_map SEC(".maps");

static inline __attribute__((always_inline)) bool has_match_binaries(__u32 selidx)
{
	return map_lookup_elem(&tg_mb_sel_opts, &selidx) != 0;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_binaries(__u32 selidx, struct execve_map_value *current)
{
	struct match_binaries_sel_opts *selector_options;
	bool match = 0;
	void *path_map;
	__u8 *found_key;
#ifdef __LARGE_BPF_PROG
	struct string_prefix_lpm_trie *prefix_key;
	struct string_postfix_lpm_trie *postfix_key;
	__u64 postfix_len = STRING_POSTFIX_MAX_MATCH_LENGTH - 1;
	long ret;
	int zero = 0;
#endif

#ifdef __LARGE_BPF_PROG
	prefix_key = map_lookup_elem(&file_prefix_lpm_heap, &zero);
	if (!prefix_key)
		return 0;
#endif

	if (!current) {
		// this should not happen, it means that the process was missed when
		// scanning /proc for process that started before and after tetragon
		return 0;
	}

	// retrieve the selector_options for the matchBinaries, if it's NULL it
	// means there is not matchBinaries in this selector.
	selector_options = map_lookup_elem(&tg_mb_sel_opts, &selidx);
	if (selector_options) {
		if (selector_options->op == op_filter_none)
			return 1; // matchBinaries selector is empty <=> match

		if (current->bin.path_length < 0) {
			// something wrong happened when copying the filename to execve_map
			return 0;
		}

		switch (selector_options->op) {
		case op_filter_in:
			/* Check if we match the selector's bit in ->mb_bitset, which means that the
			 * process matches a matchBinaries section with a followChidren:true
			 * attribute either because the binary matches or because the binary of a
			 * parent matched.
			 */
			if (current->bin.mb_bitset & (1UL << selector_options->mbset_id))
				return 1;
			fallthrough;
		case op_filter_notin:
			path_map = map_lookup_elem(&tg_mb_paths, &selidx);
			if (!path_map)
				return 0;
			found_key = map_lookup_elem(path_map, current->bin.path);
			break;
#ifdef __LARGE_BPF_PROG
		case op_filter_str_prefix:
		case op_filter_str_notprefix:
			path_map = map_lookup_elem(&string_prefix_maps, &selector_options->map_id);
			if (!path_map)
				return 0;
			// prepare the key on the stack to perform lookup in the LPM_TRIE
			memset(prefix_key, 0, sizeof(struct string_prefix_lpm_trie));
			prefix_key->prefixlen = current->bin.path_length * 8; // prefixlen is in bits
			ret = probe_read_kernel(prefix_key->data, current->bin.path_length & (STRING_PREFIX_MAX_LENGTH - 1), current->bin.path);
			if (ret < 0)
				return 0;
			found_key = map_lookup_elem(path_map, prefix_key);
			break;
		case op_filter_str_postfix:
		case op_filter_str_notpostfix:
			path_map = map_lookup_elem(&string_postfix_maps, &selector_options->map_id);
			if (!path_map)
				return 0;
			if (current->bin.path_length >= 0 && current->bin.path_length < STRING_POSTFIX_MAX_MATCH_LENGTH)
				postfix_len = current->bin.path_length;
			postfix_key = (struct string_postfix_lpm_trie *)map_lookup_elem(&string_postfix_maps_heap, &zero);
			if (!postfix_key)
				return 0;
			postfix_key->prefixlen = postfix_len * 8; // prefixlen is in bits
			if (!current->bin.reversed) {
				file_copy_reverse((__u8 *)current->bin.end_r, postfix_len, (__u8 *)current->bin.end, current->bin.path_length - postfix_len);
				current->bin.reversed = true;
			}
			asm volatile("%[postfix_len] &= %1 ;\n" // to make 5.4 kernels happy
				     : [postfix_len] "+r"(postfix_len)
				     : "i"(STRING_POSTFIX_MAX_LENGTH - 1));
			if (postfix_len < STRING_POSTFIX_MAX_MATCH_LENGTH)
				if (probe_read(postfix_key->data, postfix_len, current->bin.end_r) < 0)
					return 0;
			found_key = map_lookup_elem(path_map, postfix_key);
			break;
#endif
		default:
			// should not happen
			return 0;
		}

		match = !!found_key;
		return is_not_operator(selector_options->op) ? !match : match;
	}

	// no matchBinaries selector <=> match
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_operations(__u32 sel_idx, __u32 action)
{
	__u32 max = 0xffffffff; // UINT32_MAX
	__u32 *op, *val;
	void *file_ops_map;

	file_ops_map = map_lookup_elem(&file_ops_maps, &sel_idx);
	if (!file_ops_map) /* no matchOperations for this selector */
		return 1;

	op = map_lookup_elem(file_ops_map, &max);
	if (op) {
		val = map_lookup_elem(file_ops_map, &action);
		if (*op == op_filter_in) {
			if (!val)
				return 0;
		} else if (*op == op_filter_notin) {
			if (val)
				return 0;
		}

		return 1;
	}

	// If 'max' not found in file_ops_map this means that we don't have any
	// matchOperations selectors.
	return 1;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct digest_key);
	__uint(max_entries, 1);
} digest_key_heap SEC(".maps");

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_digests(__u32 sel_idx, struct digest_key *digest, __u32 action)
{
	void *file_digests_map;
	struct digest_key *op_key;
	__u32 *op, *val;
	__s32 algo, zero = 0;

	// the event does not support digests yet, so accept
	if (digest == 0)
		return 1;

	// only applicable to exec events
	if (action != action_exec)
		return 1;

	op_key = map_lookup_elem(&digest_key_heap, &zero);
	if (!op_key)
		return 0;

	memset(op_key->digest, 0, sizeof(__u8) * IMA_MAX_DIGEST_SIZE);
	op_key->algo = 0x7fffffff; // INT32_MAX
	op_key->ok = 0;

	// failed to get digest
	probe_read_kernel(&algo, sizeof(algo), (__u8 *)digest + offsetof(struct digest_key, algo));
	if (algo < 0)
		return 0;

	file_digests_map = map_lookup_elem(&file_digests_maps, &sel_idx);
	if (!file_digests_map) /* no matchDigests for this selector */
		return 1;

	op = map_lookup_elem(file_digests_map, op_key);
	if (op) {
		probe_read_kernel(op_key, sizeof(*op_key), digest);
		val = map_lookup_elem(file_digests_map, op_key);
		if (*op == op_filter_in) {
			if (!val)
				return 0;
		} else if (*op == op_filter_notin) {
			if (val)
				return 0;
		}

		return 1;
	}

	// If 'max' not found in file_digests_map this means that we don't have any
	// matchDigests selectors.
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_capabilities(__u32 sel_idx)
{
	struct file_sel_caps *sel_caps;
	struct msg_capabilities *c;
	const struct cred *cred;
	struct task_struct *task;
	__u32 zero = 0;
	__u64 caps;

	c = map_lookup_elem(&file_msg_caps_heap, &zero);
	if (!c)
		return 0;

	sel_caps = map_lookup_elem(&file_capabilities_map, &sel_idx);
	if (!sel_caps) // no matchOperations for this selector
		return 1;

	task = (struct task_struct *)get_current_task();
	if (!task)
		return 0; // we cannot apply matchCapabilities without the task_struct

	cred = BPF_CORE_READ(task, cred);
	if (!cred)
		return 0; // we cannot apply matchCapabilities without task->cred

	__get_caps(c, cred);

	if (sel_caps->type > caps_inheritable)
		return 0; // We should not reach that. Userspace checks that, but we need to do some bound checking.

	caps = c->c[sel_caps->type];

	if (sel_caps->op == op_filter_in)
		return (caps & sel_caps->filter) ? 1 : 0;
	return (caps & sel_caps->filter) ? 0 : 1; // op_filter_notin
}

// same as get_namespaces(struct msg_ns *msg, struct task_struct *task) but tries to use less stack space
static inline __attribute__((always_inline)) void __get_namespaces(struct msg_ns *msg, struct task_struct *task)
{
	msg->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
	msg->ipc_inum = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
	msg->mnt_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	{
		struct pid *p = BPF_CORE_READ(task, thread_pid);
		if (p) {
			int level = BPF_CORE_READ(p, level);
			msg->pid_inum = BPF_CORE_READ(p, numbers[level].ns, ns.inum);
		} else
			msg->pid_inum = 0;
	}

	msg->pid_for_children_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	msg->net_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

	// this also includes time_ns_for_children
	if (bpf_core_field_exists(((struct nsproxy *)0)->time_ns)) {
		msg->time_inum = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
		msg->time_for_children_inum = BPF_CORE_READ(task, nsproxy, time_ns_for_children, ns.inum);
	}

	msg->cgroup_inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	msg->user_inum = BPF_CORE_READ(task, mm, user_ns, ns.inum);
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_namespaces(__u32 sel_idx)
{
	struct file_sel_namespaces *sel_ns;
	struct task_struct *task;
	struct msg_ns *n;
	__u32 i = 0;

	n = map_lookup_elem(&file_msg_ns_heap, &i);
	if (!n)
		return 0;

	sel_ns = map_lookup_elem(&file_namespaces_map, &sel_idx);
	if (!sel_ns) // no matchOperations for this selector
		return 1;

	task = (struct task_struct *)get_current_task();
	if (!task)
		return 0; // we cannot apply matchNamespaces without the task_struct

	__get_namespaces(n, task);

#ifndef __ENABLE_GLOB_SUPPORT
#pragma unroll
#endif
	for (i = 0; i < ns_max_types; ++i) {
		if (sel_ns->filter.filter[i] == NS_FILTER_HOST && (sel_ns->ns.inum[i] != n->inum[i]))
			return 0;
		if (sel_ns->filter.filter[i] == NS_FILTER_NOHOST && (sel_ns->ns.inum[i] == n->inum[i]))
			return 0;
	}
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_rename(__u32 sel_idx, __u32 action, __u32 flags)
{
	struct file_sel_rename *sel;

	// only applicable to rename events
	if (action != action_rename)
		return 1;

	sel = map_lookup_elem(&file_rename_map, &sel_idx);
	if (!sel) // no matchRenameSrcType for this selector
		return 1;

	// the agent ensures that this is always in
	if (sel->op != op_filter_in)
		return 0;

	// The user sets SRC_REG_FILE or SRC_DIRECTORY in sel->matchMask.
	// We compare that with the flags computed in the kprobe/vfs_rename program.
	return (sel->matchMask & flags) != 0;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_open_flags(__u32 sel_idx, __u32 action, __u32 flags)
{
	void *inner_open_flags_map;
	struct onflags *of;
	int i = 0;

	// only applicable to open events
	if (action != action_open && action != action_openraw)
		return 1;

	inner_open_flags_map = map_lookup_elem(&file_open_flags_map, &sel_idx);
	if (!inner_open_flags_map) // no matchOpenFlags for this selector
		return 1;

	for (i = 0; i < MAX_SELECTOR_OPEN_FLAGS; ++i) {
		__u32 k = i;
		of = map_lookup_elem(inner_open_flags_map, &k);
		if (of) {
			if (of->op == 0) // no more operators
				break;

			// The first part of this expression matches on the acc mode (i.e. O_RDONLY, O_RDWR, or O_WRONLY)
			// The secondd part of this expression matches on the other open flags and we require at least
			// those that are defined in the selector to match. Having more than those, results also in a match.
			bool rs = ((flags & ~O_ACCMODE) & of->mask) == of->mask;
			if (of->has_acc_mode)
				rs = ((flags & O_ACCMODE) == of->acc_mode) && rs;

			if (of->op == op_filter_in && rs)
				return 1;
			else if (of->op == op_filter_notin && !rs)
				return 1;
		}
	}

	// nothing matches here
	return 0;
}

#ifdef __ENABLE_GLOB_SUPPORT
struct pattern_loop_ctx {
	__u32 sel_idx;
	char *path;
	__u32 len;
	int ret;
};

static long pattern_loop_cb(u32 index, void *_ctx)
{
	struct pattern_loop_ctx *ctx = (struct pattern_loop_ctx *)_ctx;
	struct pattern_key key;
	void *inner_pattern_map;

	key.sel_idx = ctx->sel_idx;
	key.pattern_idx = index;

	inner_pattern_map = map_lookup_elem(&glob_patterns_map, &key);
	if (!inner_pattern_map) { // no matchFilename for this selector (i == 0) *or* none of the previous patterns match (i != 0)
		ctx->ret = index == 0;
		return 1; // we match
	}

	ctx->ret = check_pattern(inner_pattern_map, ctx->path, ctx->len);
	if (ctx->ret == 1)
		return 1; // we match and stop

	if (ctx->ret != 0) {
		// TODO: report errors better
		ctx->ret = 0; // do not match on errors
		return 0; // error -- continue on the next pattern
	}

	return 0; // no match -- continue on the next pattern
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_filename(__u32 sel_idx, char *path, __u32 len, struct digest_key *digest)
{
	struct pattern_loop_ctx ctx = {
		.sel_idx = sel_idx,
		.path = path,
		.len = len,
		.ret = 0,
	};
	__u32 sel = sel_idx, *op = 0;

	if (!path) // no path in eval_selectors call, inode-based hooks do not support that
		return 1;

	op = map_lookup_elem(&filename_ops_map, &sel);
	if (!op) // no matchFilename for this selector -- match
		return 1;

	if (*op == match_filename_in_pattern) {
		loop(256, &pattern_loop_cb, &ctx, 0); // maximum 256 patterns per selector
		return ctx.ret;
	} else if (*op == match_filename_in_file_with_digest) {
		void *path_map, *digest_map, *tmp_digest;
		struct full_path *tmp_path;
		__u32 *path_idx, *digest_idx;
		int zero = 0;

		tmp_path = map_lookup_elem(&filename_heap_map, &zero);
		if (!tmp_path)
			return 0;

		len &= (MAX_FILEPATH_SIZE - 1);
		memset(tmp_path->path, 0, MAX_FILEPATH_SIZE);
		probe_read_kernel(tmp_path->path, len, path);

		path_map = map_lookup_elem(&filename_path_map, &sel);
		if (!path_map) // no matchFilename for this selector -- match
			return 1;

		path_idx = map_lookup_elem(path_map, tmp_path->path);
		if (!path_idx) // no path in the allowed paths -- do no match
			return 0;

		if (!digest) // we have matched the path but no digest -- do not match
			return 0;

		digest_map = map_lookup_elem(&filename_digest_map, &sel);
		if (!digest_map) // we have matched the path but digest does not exist for this selector-- do not match
			return 0;

		tmp_digest = map_lookup_elem(&digest_heap_map, &zero);
		if (!tmp_digest)
			return 0;

		probe_read_kernel(tmp_digest, sizeof(struct digest_key), digest);

		digest_idx = map_lookup_elem(digest_map, tmp_digest);
		if (!digest_idx) // no digest in the allowed digests -- do no match
			return 0;

		// if both (path and digest) exist and the value is the same then match
		return (*path_idx == *digest_idx);
	}

	return 0;
}
#endif /* __ENABLE_GLOB_SUPPORT */

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_exec_attributes(__u32 sel_idx, __u32 action, __u32 flags)
{
	__u8 is_exe_upper_layer, is_exe_from_memfd;
	__u32 sel = sel_idx;
	struct exec_attr *v;
	union exec_flags f;

	f.d32 = flags;
	is_exe_from_memfd = f.d8[EXEC_ATTR_MEMFD_IDX];
	is_exe_upper_layer = f.d8[EXEC_ATTR_UPPER_IDX];

	// only applicable to open events
	if (action != action_exec)
		return 1;

	v = map_lookup_elem(&exec_attributes_map, &sel);
	if (!v) // no matchExecAttr for this selector -- match
		return 1;

	if (v->is_exe_upper_layer != MATCH_EXEC_ATTR_ANY) {
		if (v->is_exe_upper_layer != is_exe_upper_layer)
			return 0; // event value is different from selector value -- do no match
	}

	if (v->is_exe_from_memfd != MATCH_EXEC_ATTR_ANY) {
		if (v->is_exe_from_memfd != is_exe_from_memfd)
			return 0; // event value is different from selector value -- do no match
	}

	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_openraw_result(__u32 sel_idx, __u32 action, __s32 result)
{
	__u32 sel = sel_idx;
	__u32 *sel_res = 0;

	// only applicable to openraw events
	if (action != action_openraw)
		return 1;

	// skip that selector due to enforcement
	if (result == 0x7FFFFFFF) // INT32_MAX
		return 1;

	sel_res = map_lookup_elem(&file_openraw_result_map, &sel);
	if (!sel_res) // no matchOpenrawResult for this selector -- match
		return 1;

	if (*sel_res == SEL_OPENRAW_SUCCESS) // match succeed open call
		return result > 0;
	else if (*sel_res == SEL_OPENRAW_FAILURE) // match failed open call
		return result < 0;

	return 0;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_uid_gid(__u32 sel_idx)
{
	__u32 sel = sel_idx;
	struct sel_uidgid *val = 0;
	__u64 uid_gid = get_current_uid_gid();
	__u32 gid = uid_gid >> 32;
	__u32 uid = uid_gid & 0xFFFFFFFFUL;

	val = map_lookup_elem(&file_uidgid_map, &sel);
	if (!val) // no matchidGid for this selector -- match
		return 1;

	if (val->uid_op == op_filter_in) {
		if (uid == val->uid_val)
			goto sel_check_gid;
		return 0; // do not match
	} else if (val->uid_op == op_filter_notin) {
		if (uid != val->uid_val)
			goto sel_check_gid;
		return 0; // do not match
	}

sel_check_gid:
	if (val->gid_op == op_filter_in)
		return gid == val->gid_val;
	else if (val->gid_op == op_filter_notin)
		return gid != val->gid_val;

	// we already matched uid here but we didn't have to check gid, so match
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_binary_properties(__u32 sel_idx, __u32 action, __u32 secureexec)
{
	__u32 sel = sel_idx;
	struct sel_binprop *val = 0;

	// only applicable to exec events
	if (action != action_exec)
		return 1;

	// secureexec is not set
	if (secureexec == INVALID_SECUREEXEC)
		return 1;

	val = map_lookup_elem(&file_binprop_map, &sel);
	if (!val) // no matchBinaryProperties for this selector -- match
		return 1;

	if (val->secureexec_op == op_filter_in)
		return (val->secureexec_val & secureexec) != 0;
	else if (val->secureexec_op == op_filter_notin)
		return (val->secureexec_val & secureexec) == 0;

	// we should not reach this point (i.e. do not match)
	return 0;
}

static inline __attribute__((always_inline)) bool has_match_proc_dur(__u32 selidx)
{
	return map_lookup_elem(&file_proc_dur_map, &selidx) != 0;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_proc_dur(__u32 sel_idx, struct execve_map_value *execve)
{
	__u32 sel = sel_idx;
	struct sel_proc_dur *val = 0;
	__u64 curr_time = 0;
	__u64 process_duration = 0;

	val = map_lookup_elem(&file_proc_dur_map, &sel);
	if (!val) // no matchProcessDuration for this selector -- match
		return 1;

	curr_time = tg_get_ktime();
	if (curr_time < execve->key.ktime) // current time should always be greater than process init time
		return 0;

	process_duration = curr_time - execve->key.ktime;
	if (val->op == op_filter_gt)
		return process_duration > val->val;
	else if (val->op == op_filter_lt)
		return process_duration < val->val;
	return 0; // we make sure in the user-space that op is Gt or Lt
}

static inline __attribute__((always_inline)) __u32
__eval_selectors(__u32 sel_idx, struct sel_args args, struct digest_key *digest, struct sel_path path, __u32 *msg_id)
{
	struct file_actions_val *act = 0;

#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_OPERATIONS) {
#endif
		if (!check_match_operations(sel_idx, args.action))
			return 0;
#ifdef __LARGE_BPF_PROG
	}
#endif
#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_UID_GID) {
#endif
		if (!check_match_uid_gid(sel_idx))
			return 0;
#ifdef __LARGE_BPF_PROG
	}
#endif
#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_BINARY_PROPERTIES) {
#endif
		if (!check_match_binary_properties(sel_idx, args.action, args.secureexec))
			return 0;
#ifdef __LARGE_BPF_PROG
	}
#endif
#ifdef __LARGE_BPF_PROG
#ifdef __FILE_DIGEST_LSM
	if (HAS_MATCH_DIGESTS) {
		if (!check_match_digests(sel_idx, digest, args.action))
			return 0;
	}
#endif
	if (HAS_MATCH_NAMESPACES) {
		if (!check_match_namespaces(sel_idx))
			return 0;
	}
	if (HAS_MATCH_CAPABILITIES) {
		if (!check_match_capabilities(sel_idx))
			return 0;
	}
	if (HAS_MATCH_OPEN_FLAGS) {
		if (!check_match_open_flags(sel_idx, args.action, args.flags))
			return 0;
	}
	if (HAS_MATCH_EXEC_ATTRIBUTES) {
		if (!check_match_exec_attributes(sel_idx, args.action, args.flags))
			return 0;
	}
#endif
#ifdef __ENABLE_OPENRAW_SUPPORT
#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_OPENRAW_RESULT) {
#endif
		if (!check_match_openraw_result(sel_idx, args.action, args.retval))
			return 0;
#ifdef __LARGE_BPF_PROG
	}
#endif
#endif
#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_RENAME_SRC_TYPE) {
#endif
		if (!check_match_rename(sel_idx, args.action, args.flags))
			return 0;
#ifdef __LARGE_BPF_PROG
	}
#endif
#ifdef __LARGE_BPF_PROG
	if (HAS_MATCH_PROCESS_DURATION || HAS_MATCH_BINARIES) {
#endif
		// here we need to call event_find_curr()
		if (has_match_binaries(sel_idx) || has_match_proc_dur(sel_idx)) {
			struct execve_map_value *execve;
			bool walker = 0;
			__u32 ppid;

			execve = event_find_curr(&ppid, &walker);
			if (execve) {
#ifdef __LARGE_BPF_PROG
				if (HAS_MATCH_PROCESS_DURATION) {
#endif
					if (!check_match_proc_dur(sel_idx, execve))
						return 0;
#ifdef __LARGE_BPF_PROG
				}
#endif
#ifdef __LARGE_BPF_PROG
				if (HAS_MATCH_BINARIES) {
#endif
					if (!check_match_binaries(sel_idx, execve))
						return 0;
#ifdef __LARGE_BPF_PROG
				}
#endif
			}
		}
#ifdef __LARGE_BPF_PROG
	}
#endif
#ifdef __ENABLE_GLOB_SUPPORT
	if (HAS_MATCH_FILENAME) {
		if (!check_match_filename(sel_idx, path.path, path.len, digest))
			return 0;
	}
#endif

	act = map_lookup_elem(&file_actions_map, &sel_idx);
	if (act) {
		if (msg_id)
			*msg_id = act->msg_id;
		return act->val;
	}
	return 0;
}

#ifdef __V61_BPF_PROG
struct selectors_ctx {
	char *path;
	__u32 len;
	__u32 retval;
	__u32 action;
	__u32 flags;
	__s32 ret;
	__u32 num_selectors;
	__u32 msg_id;
	__u32 secureexec;
	struct digest_key *digest;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct selectors_ctx);
	__uint(max_entries, 1);
} selectors_ctx_heap SEC(".maps");

static long selectors_cb(u32 index, void *ununsed)
{
	struct selectors_ctx *ctx;
	__u32 zero = 0;

	ctx = map_lookup_elem(&selectors_ctx_heap, &zero);
	if (!ctx)
		return 0;

	if (index >= ctx->num_selectors) // no need to check more selectors
		return 1;

	ctx->retval = __eval_selectors(index, (struct sel_args){ .action = ctx->action, .flags = ctx->flags, .retval = ctx->ret, .secureexec = ctx->secureexec }, ctx->digest, (struct sel_path){ ctx->path, ctx->len }, &ctx->msg_id);
	if (ctx->retval) { // we return the value from the first selector that matches
		return 1;
	}

	return 0;
}
#endif

// return true if the policy_filter check matche the policy_id
static inline __attribute__((always_inline)) bool policy_filter_match()
{
	struct file_config_map_value *conf;
	__u32 zero = 0;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return false;

	return policy_filter_check(conf->policy_id);
}

static inline __attribute__((always_inline)) __u32
eval_selectors(struct sel_args args, struct digest_key *digest, struct sel_path path, __u32 *msg_id)
{
	struct file_config_map_value *conf;
	__u32 zero = 0;
#ifndef __V61_BPF_PROG
	__u32 i, val = 0;
#else
	struct selectors_ctx *ctx;
#endif

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return 0;

	// no selectors, post all events
	if (conf->num_selectors == 0)
		return FILE_OP_POST;

#ifdef __V61_BPF_PROG
	ctx = map_lookup_elem(&selectors_ctx_heap, &zero);
	if (!ctx)
		return 0;

	ctx->action = args.action;
	ctx->flags = args.flags;
	ctx->ret = args.retval;
	ctx->secureexec = args.secureexec;
	ctx->path = path.path;
	ctx->len = path.len;
	ctx->retval = 0;
	ctx->num_selectors = conf->num_selectors;
	ctx->digest = digest;
	ctx->msg_id = 0;

	loop(128, &selectors_cb, 0, 0);
	if (msg_id)
		*msg_id = ctx->msg_id;
	if (ctx->retval)
		return ctx->retval;
#else /* __V61_BPF_PROG */
#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif /* __LARGE_BPF_PROG */
	for (i = 0; i < MAX_FIM_SELECTORS; ++i) {
		if (i >= conf->num_selectors) // no need to check more selectors
			break;
		val = __eval_selectors(i, args, digest, path, msg_id);
		if (val) // we return the value from the first selector that matches
			return val;
	}
#endif /* __V61_BPF_PROG */
	return 0; // not selector matches
}

static inline __attribute__((always_inline)) int get_tp_id()
{
	__u32 zero = 0;
	struct file_config_map_value *conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return 0;
	return conf->tp_id;
}

// Similar to event_find_curr() but it uses a specific task (instead of current)
static inline __attribute__((always_inline)) struct execve_map_value *event_find_curr_task(struct task_struct *task)
{
	struct execve_map_value *value = 0;
	int pid, i;

	probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));

#pragma unroll
	for (i = 0; i < 4; i++) {
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		probe_read_kernel(&task, sizeof(task), _(&task->real_parent));
		if (!task)
			break;
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
	}
	return value;
}

static inline __attribute__((always_inline)) struct msg_file_ops *get_msg_init()
{
	struct msg_file_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_heap_map, &zero);
	if (!msg) {
		// This map_lookup_elem is just used to add a reference to policy_conf map in all FIM programs to avoid warnings similar to:
		// "failed to open bpf map /sys/fs/bpf/tetragon/fim-ro-protection-policy-proc-protection/policy_conf: no such file or directory"
		// This is already used in all path-based programs and inode-based programs in enforcement mode, but we miss that in inode-based
		// programs in observability mode.
		//
		// We add this in an error path to not having any overheads in the common path.:
		map_lookup_elem(&policy_conf, &zero);

		return 0;
	}

	memset(msg, 0, sizeof(struct msg_file_ops));

	msg->common.op = ISO_MSG_OP_FILE;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;
	msg->common.size = sizeof(struct msg_file_ops);
	msg->common.ktime = tg_get_ktime();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}
	msg->current.pad[0] = 0;
	msg->current.pad[1] = 0;
	msg->current.pad[2] = 0;
	msg->current.pad[3] = 0;
	msg->secureexec = 0;

	return msg;
}

static inline __attribute__((always_inline)) int
filter_match(struct bpf_lpm_trie_key *key, __u32 *rule_id)
{
	struct lpm_val *retval = map_lookup_elem(&lpm_trie_map_alloc, key);
	if (retval) {
		if (rule_id)
			*rule_id = retval->rule;
		return retval->action;
	}
	return FILTER_NOTFOUND;
}

static inline __attribute__((always_inline)) __u32 get_mnt_ns()
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

/*
 * There are cases in overlayfs where stat reports a different device ID 
 * compared to what inode* contains. As we use stat from the user-space
 * to get <ino, dev_id> this may result in missing several file accesses.
 * 
 * In order to have this case, we should have xino = OFF and not all the 
 * overlayfs layers be in the same file system.
 * 
 * This function returns the device ID are returned by stat in overlayfs
 * (https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/inode.c#L97)
 */
static inline __attribute__((always_inline)) void fix_dev_id_ovl(struct inode *inode, struct dentry *dentry, __u64 *ino, __u32 *dev)
{
	// we care only for inodes in overlayfs
	if (BPF_CORE_READ(dentry, d_sb, s_magic) != OVERLAYFS_SUPER_MAGIC)
		return;

	if (!ino || !dev)
		return;

	ovl_getattr(inode, dentry, ino, dev);
}

static inline __attribute__((always_inline)) void
get_fs_info(struct msg_fs_info *msg, __u64 *ino, struct inode *inode, struct dentry *dentry)
{
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);

	msg->dev = BPF_CORE_READ(sb, s_dev);
	msg->pad = 0;
	probe_read_kernel(msg->id, MSG_FS_INFO_ID_LEN * sizeof(char), _(&(sb->s_id[0])));
	probe_read_str(msg->name, MSG_FS_INFO_NAME_LEN * sizeof(char), BPF_CORE_READ(sb, s_type, name));
	probe_read_kernel(msg->uuid, MSG_FS_INFO_UUID_LEN * sizeof(char), _(&sb->s_uuid));

#ifdef __LARGE_BPF_PROG
	if (bpf_core_type_exists(struct ovl_entry))
		fix_dev_id_ovl(inode, dentry, ino, &(msg->dev));
#endif
}

static inline __attribute__((always_inline)) void
get_ino_fs(struct msg_file_ops *msg, struct inode *inode, struct dentry *dentry)
{
	msg->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	get_fs_info(&(msg->fs), &(msg->ino), inode, dentry);
}

static inline __attribute__((always_inline)) void
get_parent_ino_fs(struct msg_file_ops *msg, struct dentry *dentry)
{
	struct inode *inode;

	inode = BPF_CORE_READ(dentry, d_inode);
	msg->parent_ino = BPF_CORE_READ(inode, i_ino);

	get_fs_info(&(msg->parent_fs), &(msg->parent_ino), inode, dentry);
}

static inline __attribute__((always_inline)) struct inode_val *
find_inode_in_map(struct bpf_map_def *inode_map, __u64 ino, __u32 dev)
{
	struct inode_key file_key;

	file_key.ino = ino;
	file_key.dev_major = MAJOR(dev);
	file_key.dev_minor = MINOR(dev);

	return map_lookup_elem(inode_map, &file_key);
}

static inline __attribute__((always_inline)) void inc_error(__u32 hook, int metric)
{
	__u32 zero = 0;
	struct file_errors *valp;

	if (metric >= FILE_ERR_MAX || metric < 0)
		metric = FILE_ERR_UNEXPECTED;

	valp = map_lookup_elem(&file_errors_map, &zero);
	if (valp)
		__sync_fetch_and_add(&valp->m[hook][metric], 1);
}

static inline __attribute__((always_inline)) int handle_enforcement(int err)
{
	__u32 zero = 0, polacct = POLICY_INVALID_ACT_;
	struct policy_stats *pstats;
	struct policy_conf *pcnf;
	int retval = 0;

	// no need to override, so just return
	if (!(err & FILE_OP_BLOCK))
		return 0;

	pcnf = map_lookup_elem(&policy_conf, &zero);
	if (pcnf && pcnf->mode == POLICY_MODE_ENFORCE) {
		retval = -EPERM;
		polacct = POLICY_OVERRIDE;
	} else {
		retval = 0;
		polacct = POLICY_MONITOR_OVERRIDE;
	}

	if (polacct != POLICY_INVALID_ACT_) {
		pstats = map_lookup_elem(&policy_stats, &zero);
		if (pstats)
			lock_add(&pstats->act_cnt[polacct], 1);
	}

	return retval;
}

// <  0 for error
// == 0 ignore
// >  0 match
static inline __attribute__((always_inline)) int path_prefix_matcher(char *path, __u32 size, __u32 *rule_id, struct file_config_map_value *conf)
{
	struct bpf_lpm_trie_key *key = 0;
	int zero = 0, action = 0;

	// although we care about files inside this directory
	// we may have this specific file path in the exclude
	// list now we check the trie with the initial paths
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return -FILE_ERR_GET_TRIE_HEAP;

	key->prefixlen = size * 8;
	memcpy(key->data, path, 256);

	action = filter_match(key, rule_id);
	if (action == FILTER_NOTFOUND || action == FILTER_IGNORE || action == FILTER_MONITOR)
		return FILTER_IGNORE;
	return FILTER_MATCH;
}

// <  0 for error
// == 0 ignore
// >  0 match
static inline __attribute__((always_inline)) int path_pattern_matcher(char *path, __u32 size, __u32 *rule_id, struct file_config_map_value *conf)
{
	for (int i = 0; i < MAX_FILE_PATTERNS; i++) {
		struct pattern_val *val;
		int idx = i;

		if (idx >= conf->num_patterns)
			break;

		val = map_lookup_elem(&patterns_map_alloc, &idx);
		if (!val)
			return -FILE_ERR_GET_PATTERN_MAP;

		// Prefix and suffix overlap. Do not match.
		if (val->prefix_len + val->suffix_len > size)
			continue;

		// First try to match the prefix.
		//
		// In most cases we use an LPM to match a prefix. Here we do a simple
		// for-loop for that check.
		//
		// Consider the following rules:
		// 1. prefix: "/home/aaa/" suffix: ".sh"
		// 2. prefix: "/home/" suffix: ".txt"
		//
		// If we have a path "/home/aaa/bbb.txt" it will always match the
		// first rule due to the Longest part of LPM. So we would never
		// compare with the suffix of the second rule. We could try to do
		// something more "clever", but as long as a simple for-loop works
		// there is no need to spend more time on this for now.
		for (int j = 0; j < MAX_COMPONENT_SIZE; j++) {
			if (j >= val->prefix_len - 1)
				break;
			if (path[j] != val->prefix[j])
				goto try_next_pattern;
		}

		// Once the prefix is matched, try to match the suffix.
		for (int j = 0; j < MAX_COMPONENT_SIZE; j++) {
			int offset = size - val->suffix_len;
			if (offset < 0 || offset > MAX_COMPONENT_SIZE)
				goto try_next_pattern;
			if (j >= val->suffix_len - 1)
				break;
			if (path[j + offset] != val->suffix[j])
				goto try_next_pattern;
		}

		if (rule_id)
			*rule_id = val->rule;

		// Here we have matched both.
		return FILTER_MATCH;

	try_next_pattern: // Need an empty statement after that. Otherwise we got an error to have a label before the '}'.
		;
	}

	return FILTER_IGNORE;
}

// <  0 for error
// == 0 ignore
// >  0 match
static inline __attribute__((always_inline)) int file_exact_matcher(char *path, __u32 size, __u32 *rule_id, struct file_config_map_value *conf)
{
	__u32 *ret;

	ret = map_lookup_elem(&exact_match_map_alloc, path);
	if (!ret)
		return FILTER_IGNORE;

	if (rule_id)
		*rule_id = *ret;

	return FILTER_MATCH;
}

typedef int (*matcher_type)(char *, __u32, __u32 *, struct file_config_map_value *);

#ifdef __LARGE_BPF_PROG
#define MATCHERS_LEN 3
#else
#define MATCHERS_LEN 1
#endif

// <  0 for error
// == 0 ignore
// >  0 match
static inline __attribute__((always_inline)) int eval_patterns(char *path, __u32 size, __u32 *rule_id, struct file_config_map_value *conf)
{
	matcher_type matchers[3] = { path_prefix_matcher, path_pattern_matcher, file_exact_matcher };
	int ret, i;

	for (i = 0; i < MATCHERS_LEN; ++i) {
		ret = (matchers[i])(path, size, rule_id, conf);
		if (ret) // if there was a match or an error, return
			return ret;
	}

	return FILTER_IGNORE;
}

static inline __attribute__((always_inline)) int generate_new_file_path(struct dentry *dentry, struct msg_file_ops *msg, struct inode_val *file_val)
{
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 path_size = 0;
	struct qstr d_name;
	char *buffer;
	int zero = 0;

	// we care about files inside this directory
	// get a buffer to generate its path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return -FILE_ERR_GET_BUFFER_HEAP;

	// first write the dentry name
	probe_read_kernel(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n"
		     : [dlen_size] "+r"(dlen_size));
	dlen_offset = MAX_FILEPATH_SIZE;
	probe_read_kernel(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// then write the directory name
	// this is what we have in the map already (we don't traverse anything)
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n"
		     : [dir_size] "+r"(dir_size));
	dir_offset = MAX_FILEPATH_SIZE - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n"
		     : [dir_offset] "+r"(dir_offset));
	probe_read_kernel(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	// set the filepath inside msg
	asm volatile("%[path_size] &= 0xff;\n"
		     : [path_size] "+r"(path_size));
	probe_read_kernel(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	return 0;
}

static inline __attribute__((always_inline)) void
__generate_path(struct path *path, char *buf, __u32 bufsz, __u32 *sz, __u32 *flags)
{
	int error = 0, buflen = 0;
	char *p;

#ifdef __LARGE_BPF_PROG
	if (USE_BPF_D_PATH_HELPER) {
		long ret;

		ret = d_path(path, buf, bufsz);
		if (ret > 0)
			*sz = ret - 1;
	} else
#endif /* __LARGE_BPF_PROG */
	{
		p = d_path_local(path, &buflen, &error);
		if (!error) {
			asm volatile("%[buflen] &= 0xff;\n"
				     : [buflen] "+r"(buflen));
			probe_read_kernel(buf, buflen, p);
			*sz = buflen;
		}
	}
	*flags = PATH_BASED_FILE;
}

static inline __attribute__((always_inline)) void
generate_path(struct msg_file_path *p, struct path *path)
{
	__generate_path(path, p->str, sizeof(p->str), &p->size, &p->flags);
}

static inline __attribute__((always_inline)) void
generate_path_rename(struct msg_rename_elem *msg, struct path *path)
{
	__generate_path(path, msg->path.dir, sizeof(msg->path.dir), &msg->path.dir_size, &msg->path.flags);
}

static inline __attribute__((always_inline)) void
complete_msg(struct msg_file_ops *msg, __u32 action, __u32 hook, __u32 operation, __u32 rule_id, __u32 open_flags, __u32 msg_id)
{
	msg->action = action;
	msg->hook = hook;
	msg->ktime = tg_get_ktime();
	msg->mnt_ns = get_mnt_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();
	msg->open_flags = open_flags;
}

static inline __attribute__((always_inline)) int
generate_inode_metadata(struct msg_file_ops *msg, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct inode *inode;

	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	// get current inode and fs info
	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return -FILE_ERR_INODE_FROM_FILE;

	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return -FILE_ERR_PARENT_FROM_DENTRY;

	get_parent_ino_fs(msg, parent_dentry);

	return 0;
}

static inline __attribute__((always_inline))
__u32
run_matcher(struct inode *inode)
{
#ifdef __LARGE_BPF_PROG
	__u32 *r, s_magic, i_mode;

	if (PATH_BASED_MATCHER == FS_TYPE_MATCHER) {
		s_magic = BPF_CORE_READ(inode, i_sb, s_magic);

		// check if we care about this file system
		r = map_lookup_elem(&file_system_type_map, &s_magic);
		if (!r)
			return INVALID_RULE_ID;
		return *r;
	} else if (PATH_BASED_MATCHER == INODE_TYPE_MATCHER) {
		i_mode = BPF_CORE_READ(inode, i_mode) & S_IFMT;

		// check if we care about this inode type
		r = map_lookup_elem(&inode_type_map, &i_mode);
		if (!r)
			return INVALID_RULE_ID;
		return *r;
	} else if (PATH_BASED_MATCHER == MATCH_ALL) {
		return 0;
	}
#endif /* __LARGE_BPF_PROG */

	// make sure that the PATH_BASED_MATCHER is correctly set
	// otherwise the verifier will fail
	while (1) {
	}
	return 0;
}

// we do not care about any operations on sockets and fifos in the context of FIM
static inline __attribute__((always_inline)) bool
skip_access(struct inode *inode)
{
	umode_t i_mode = BPF_CORE_READ(inode, i_mode);

	return (S_ISSOCK(i_mode) | S_ISFIFO(i_mode)) != 0;
}

static inline __attribute__((always_inline)) int
path_generic_file_access(void *ctx, struct file *file, int action, int hook_type)
{
	__u32 operation, rule_id, msg_id = 0;
	struct io_uring_op_key key = {
		.file_ptr = (__u64)file,
		.pid_tgid = get_current_pid_tgid(),
	};
	struct io_uring_op_val *val;
	struct msg_file_ops *msg;
	struct dentry *dentry;
	int err;

	if (!policy_filter_match())
		return 0;

	if (!file)
		return -FILE_ERR_FILE_ARG;

	if (skip_access(BPF_CORE_READ(file, f_inode)))
		return 0;

	msg = get_msg_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	val = map_lookup_elem(&io_uring_map, &key);
	if (val) { // we are in the middle of io_uring operation
		struct execve_map_value *enter = event_find_curr_task(val->user_task);
		if (enter) {
			msg->current.pid = enter->key.pid;
			msg->current.ktime = enter->key.ktime;
		}
	}

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -FILE_ERR_DENTRY_FROM_FILE;

	err = generate_inode_metadata(msg, dentry);
	if (err < 0)
		return err;

	rule_id = run_matcher(BPF_CORE_READ(file, f_inode));
	if (rule_id == INVALID_RULE_ID)
		return 0;

	generate_path(&msg->path, _(&file->f_path));

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// At these events we don't need to update any internal maps.
	operation = eval_selectors((struct sel_args){ .action = action, .flags = 0, .retval = 0 }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return operation;

	complete_msg(msg, action, hook_type, operation, rule_id, 0, msg_id);

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return operation;
}

static inline __attribute__((always_inline)) void generate_path_mixed(struct msg_file_path *p, struct path *dir, struct dentry *new_dentry)
{
	__u64 path_size, dlen_size = 0;
	struct qstr d_name;

	// first copy the dir path
	generate_path(p, dir);
	path_size = p->size;

	// now write a "/" after the dentry name
	path_size &= 0xff;
	p->str[path_size] = '/';
	path_size++;

	// at the end write the dentry name
	probe_read_kernel(&d_name, sizeof(d_name), _(&new_dentry->d_name));
	dlen_size = d_name.len &= 0x3f;
	probe_read_kernel(p->str + path_size, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	p->size = path_size;
	p->flags = PATH_BASED_FILE;
}

static inline __attribute__((always_inline)) void
rename_copy_dname(struct dentry *dentry, struct msg_rename_elem *pth)
{
	struct qstr d_name;
	__u32 dlen_size = 0;

	probe_read_kernel(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n"
		     : [dlen_size] "+r"(dlen_size));
	probe_read_kernel(pth->path.name, dlen_size, (const char *)d_name.name);
	pth->path.name_size = dlen_size;
}

static inline __attribute__((always_inline)) void
init_rename_msg(struct msg_file_rename_ops *msg)
{
	struct execve_map_value *enter;
	bool walker = 0;
	__u32 ppid;

	msg->common.op = ISO_MSG_OP_FILE_RENAME;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;
	msg->common.size = sizeof(struct msg_file_rename_ops);
	msg->common.ktime = tg_get_ktime();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}
	msg->current.pad[0] = 0;
	msg->current.pad[1] = 0;
	msg->current.pad[2] = 0;
	msg->current.pad[3] = 0;

	msg->flags = 0;
}

static inline __attribute__((always_inline)) __u32
get_rename_src_flags(umode_t i_mode)
{
	__u32 flags = 0;

	if (S_ISREG(i_mode))
		flags |= SRC_REG_FILE;
	else if (S_ISDIR(i_mode))
		flags |= SRC_DIRECTORY;
	else if (S_ISCHR(i_mode))
		flags |= SRC_CHAR_DEV;
	else if (S_ISBLK(i_mode))
		flags |= SRC_BLOCK_DEV;
	else if (S_ISFIFO(i_mode))
		flags |= SRC_NAMED_PIPE;
	else if (S_ISLNK(i_mode))
		flags |= SRC_SYMLINK;
	else if (S_ISSOCK(i_mode))
		flags |= SRC_SOCKET;
	else
		flags |= SRC_INVALID;

	return flags;
}

static inline __attribute__((always_inline)) __u32
get_rename_dst_flags(umode_t i_mode)
{
	__u32 flags = 0;

	if (S_ISREG(i_mode))
		flags |= DST_REG_FILE;
	else if (S_ISDIR(i_mode))
		flags |= DST_DIRECTORY;
	else if (S_ISCHR(i_mode))
		flags |= DST_CHAR_DEV;
	else if (S_ISBLK(i_mode))
		flags |= DST_BLOCK_DEV;
	else if (S_ISFIFO(i_mode))
		flags |= DST_NAMED_PIPE;
	else if (S_ISLNK(i_mode))
		flags |= DST_SYMLINK;
	else if (S_ISSOCK(i_mode))
		flags |= DST_SOCKET;
	else
		flags |= DST_INVALID;

	return flags;
}

static inline __attribute__((always_inline)) void mod_inode_map_stats(__s64 diff)
{
	__u32 zero = 0;
	__s64 *cnt;

	cnt = map_lookup_elem(&hash_map_inode_alloc_stats, &zero);
	if (cnt)
		*cnt = *cnt + diff;
}

static inline __attribute__((always_inline)) bool is_memfd(struct file *file)
{
	unsigned long s_magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
	unsigned int i_nlink = BPF_CORE_READ(file, f_inode, i_nlink);

	return ((s_magic == TMPFS_MAGIC) || (s_magic == HUGETLBFS_MAGIC)) && (i_nlink == 0);
}

static inline __attribute__((always_inline)) bool is_dentry_upper(struct file *file)
{
#ifdef __LARGE_BPF_PROG
	enum ovl_path_type type;
	struct dentry *dentry;
	unsigned long s_magic;

	if (!bpf_core_type_exists(struct ovl_entry))
		return 0;

	s_magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
	if (s_magic != OVERLAYFS_SUPER_MAGIC)
		return false;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	type = ovl_path_type(dentry);

	return OVL_TYPE_UPPER(type) != 0;
#else
	return 0;
#endif
}
