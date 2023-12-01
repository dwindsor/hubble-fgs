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

#define MAX_FIM_SELECTORS 6

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev)    ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int)((dev)&MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

#define S_IFMT	 00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG	 0100000
#define S_IFBLK	 0060000
#define S_IFDIR	 0040000
#define S_IFCHR	 0020000
#define S_IFIFO	 0010000

#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

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

static long BPF_FUNC(ima_file_hash, struct file *file, void *dst, u32 size);
static long BPF_FUNC(d_path, struct path *path, char *buf, u32 sz);

struct mnt_idmap {
	struct user_namespace *owner;
	refcount_t count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, struct vfs_mkdir_info);
	__uint(max_entries, 1024);
} mkdir_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct vfs_mkdir_info);
	__uint(max_entries, 1);
} vfs_mkdir_info_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_retprobe_key);
	__type(value, struct vfs_rename_info);
	__uint(max_entries, 1024);
} rename_retprobe_map SEC(".maps");

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
	__type(key, struct hash_map_file_key);
	__type(value, struct hash_map_file_val);
	__uint(max_entries, 128 * 1024);
} hash_map_file_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct hash_map_file_key);
	__type(value, struct hash_map_file_val);
	__uint(max_entries, 128 * 1024);
} hash_map_dir_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct hash_map_file_val);
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
	__uint(key_size, sizeof(__u32)); /* selector id */
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
	__uint(key_size, sizeof(__u32)); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, struct digest_key);
			__type(value, __u32);
		});
} file_digests_maps SEC(".maps");

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
	__type(value, struct file_sel_namespaces);
} file_namespaces_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FIM_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, __u32);
} file_actions_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_config_map_value);
} file_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_exec_config_map_value);
} file_exec_config_map SEC(".maps");

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_binaries(__u32 selidx, struct execve_map_value *current)
{
	struct string_prefix_lpm_trie *prefix_key;
	struct match_binaries_sel_opts *selector_options;
	bool match = 0;
	void *path_map;
	__u8 *found_key;
	long ret;
	int zero = 0;

	prefix_key = map_lookup_elem(&file_prefix_lpm_heap, &zero);
	if (!prefix_key)
		return 0;

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
		case op_filter_notin:
			path_map = map_lookup_elem(&tg_mb_paths, &selidx);
			if (!path_map)
				return 0;
			found_key = map_lookup_elem(path_map, current->bin.path);
			break;
		case op_filter_str_prefix:
		case op_filter_str_notprefix:
			path_map = map_lookup_elem(&string_prefix_maps, &selector_options->map_id);
			if (!path_map)
				return 0;
			// prepare the key on the stack to perform lookup in the LPM_TRIE
			memset(prefix_key, 0, sizeof(struct string_prefix_lpm_trie));
			prefix_key->prefixlen = current->bin.path_length * 8; // prefixlen is in bits
			ret = probe_read(prefix_key->data, current->bin.path_length & (STRING_PREFIX_MAX_LENGTH - 1), current->bin.path);
			if (ret < 0)
				return 0;
			found_key = map_lookup_elem(path_map, prefix_key);
			break;
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

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_digests(__u32 sel_idx, struct digest_key *digest, __u32 action)
{
	void *file_digests_map;
	struct digest_key op_key = {
		.digest = { 0 },
		.algo = 0x7fffffff, // INT32_MAX
		.ok = 0,
	};
	__u32 *op, *val;

	// the event does not support digests yet, so accept
	if (digest == 0)
		return 1;

	// only applicable to exec events
	if (action != action_exec)
		return 1;

	// failed to get digest
	if (digest->algo < 0)
		return 0;

	file_digests_map = map_lookup_elem(&file_digests_maps, &sel_idx);
	if (!file_digests_map) /* no matchDigests for this selector */
		return 1;

	op = map_lookup_elem(file_digests_map, &op_key);
	if (op) {
		val = map_lookup_elem(file_digests_map, digest);
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

	get_namespaces(n, task);

#pragma unroll
	for (i = 0; i < ns_max_types; ++i) {
		bool same_inum = sel_ns->ns.inum[i] == n->inum[i];
		if (sel_ns->filter.filter[i] == NS_FILTER_HOST && !same_inum)
			return 0;
		if (sel_ns->filter.filter[i] == NS_FILTER_NOHOST && same_inum)
			return 0;
	}
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_enforcement(__u32 sel_idx)
{
	__u32 *action = map_lookup_elem(&file_actions_map, &sel_idx);
	if (!action)
		return 0;
	return (*action & FILE_OP_BLOCK) != 0;
}

static inline __attribute__((always_inline)) __u32
__eval_selectors(__u32 sel_idx, __u32 action, struct digest_key *digest, struct execve_map_value *execve)
{
	if (!check_match_binaries(sel_idx, execve))
		goto nopost;
	if (!check_match_operations(sel_idx, action))
		goto nopost;
	if (!check_match_digests(sel_idx, digest, action))
		goto nopost;
#ifdef __LARGE_BPF_PROG
	if (!check_match_namespaces(sel_idx))
		goto nopost;
	if (!check_match_capabilities(sel_idx))
		goto nopost;
#endif
	if (!check_enforcement(sel_idx))
		goto post;

	return FILE_OP_POST | FILE_OP_BLOCK;
post:
	return FILE_OP_POST;
nopost:
	return 0;
}

static inline __attribute__((always_inline)) __u32
eval_selectors(__u32 action, struct digest_key *digest)
{
	__u32 ppid, i, val = 0, zero = 0;
	struct file_config_map_value *conf;
	struct execve_map_value *execve;
	bool walker = 0;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return 0;

	// no selectors, post all events
	if (conf->num_selectors == 0)
		return FILE_OP_POST;

	/*
	 * Do this outside of the loop in order to reduce the number of instructions
	 * and make that work on 4.19 kernels. The check for != 0 is done close to
	 * the use as we don't know here if the selector that uses that has matchBinaries
	 * selector.
	 */
	execve = event_find_curr(&ppid, &walker);

#pragma unroll
	for (i = 0; i < MAX_FIM_SELECTORS; ++i) {
		if (i >= conf->num_selectors) // no need to check more selectors
			break;
		val = __eval_selectors(i, action, digest, execve);
		if (val) // we return the value from the first selector that matches
			return val;
	}
	return 0; // not selector matches
}

static inline __attribute__((always_inline)) __u32
__eval_exec_selectors(__u32 sel_idx, struct digest_key *digest, struct execve_map_value *execve)
{
	if (!check_match_binaries(sel_idx, execve))
		goto nopost;
	if (!check_match_digests(sel_idx, digest, action_exec))
		goto nopost;
	if (!check_match_capabilities(sel_idx))
		goto nopost;
	if (!check_match_namespaces(sel_idx))
		goto nopost;
	if (!check_enforcement(sel_idx))
		goto post;

	return FILE_OP_POST | FILE_OP_BLOCK;
post:
	return FILE_OP_POST;
nopost:
	return 0;
}

static inline __attribute__((always_inline)) __u32
eval_exec_selectors(struct digest_key *digest)
{
	__u32 ppid, i, val = 0, zero = 0;
	struct file_exec_config_map_value *conf;
	struct execve_map_value *execve;
	bool walker = 0;

	conf = map_lookup_elem(&file_exec_config_map, &zero);
	if (!conf)
		return 0;

	// no selectors, post all events
	if (conf->num_selectors == 0)
		return FILE_OP_POST;

	/*
	 * Do this outside of the loop in order to reduce the number of instructions
	 * and make that work on 4.19 kernels. The check for != 0 is done close to
	 * the use as we don't know here if the selector that uses that has matchBinaries
	 * selector.
	 */
	execve = event_find_curr(&ppid, &walker);

	for (i = 0; i < MAX_FIM_SELECTORS; ++i) {
		if (i >= conf->num_selectors) // no need to check more selectors
			break;
		val = __eval_exec_selectors(i, digest, execve);
		if (val) // we return the value from the first selector that matches
			return val;
	}

	return conf->default_action;
}

static inline __attribute__((always_inline)) int get_tp_id()
{
	__u32 zero = 0;
	struct file_config_map_value *conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return 0;
	return conf->tp_id;
}

static inline __attribute__((always_inline)) struct msg_file_ops *get_msg_init()
{
	struct msg_file_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_heap_map, &zero);
	if (!msg)
		return 0;

	msg->common.op = ISO_MSG_OP_FILE;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;
	msg->common.size = sizeof(struct msg_file_ops);
	msg->common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}
	msg->current.pad[0] = 0;
	msg->current.pad[1] = 0;
	msg->current.pad[2] = 0;
	msg->current.pad[3] = 0;

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

static inline __attribute__((always_inline)) void get_mnt_ns(__u32 *mnt_ns)
{
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct nsproxy nsp;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	probe_read(&nsp, sizeof(nsp), _(nsproxy));
	probe_read(mnt_ns, sizeof(*mnt_ns), _(&nsp.mnt_ns->ns.inum));
}

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

static inline __attribute__((always_inline)) struct ovl_layer *
ovl_layer_lower(struct dentry *dentry)
{
	struct ovl_entry *poe, oe;

	if (!dentry)
		return 0;

	probe_read(&poe, sizeof(poe), _(&dentry->d_fsdata));
	probe_read(&oe, sizeof(oe), poe);
	if (oe.numlower) {
		struct ovl_path op;
		probe_read(&op, sizeof(op),
			   (char *)poe + sizeof(struct ovl_entry));
		return (struct ovl_layer *)op.layer;
	}
	return 0;
}

// returns the fsid of the lower layer in overlayfs
// (https://elixir.bootlin.com/linux/v5.10/source/fs/overlayfs/util.c#L205)
static inline __attribute__((always_inline)) int
ovl_layer_lower_fsid(struct dentry *dentry)
{
	struct ovl_layer *l = ovl_layer_lower(dentry);
	if (l) {
		struct ovl_layer ol;
		probe_read(&ol, sizeof(ol), l);
		return ol.fsid;
	}
	return 0;
}

struct ovl_fs__old {
	struct vfsmount *upper_mnt;
	unsigned int numlower;
	/* Number of unique lower sb that differ from upper sb */
	unsigned int numlowerfs;
	struct ovl_layer *lower_layers;
	struct ovl_sb *lower_fs;
	/* workbasedir is the path at workdir= mount option */
	struct dentry *workbasedir;
	/* workdir is the 'work' directory under workbasedir */
	struct dentry *workdir;
	/* index directory listing overlay inodes by origin file handle */
	struct dentry *indexdir;
	long namelen;
	/* pathnames of lower and upper dirs, for show_options */
	struct ovl_config config;
	/* creds of process who forced instantiation of super block */
	const struct cred *creator_cred;
	bool tmpfile;
	bool noxattr;
	/* Did we take the inuse lock? */
	bool upperdir_locked;
	bool workdir_locked;
	/* Traps in ovl inode cache */
	struct inode *upperdir_trap;
	struct inode *workbasedir_trap;
	struct inode *workdir_trap;
	struct inode *indexdir_trap;
	/* Inode numbers in all layers do not use the high xino_bits */
	unsigned int xino_bits;
};

struct ovl_fs__new {
	unsigned int numlayer;
	/* Number of unique fs among layers including upper fs */
	unsigned int numfs;
	const struct ovl_layer *layers;
	struct ovl_sb *fs;
	/* workbasedir is the path at workdir= mount option */
	struct dentry *workbasedir;
	/* workdir is the 'work' directory under workbasedir */
	struct dentry *workdir;
	/* index directory listing overlay inodes by origin file handle */
	struct dentry *indexdir;
	long namelen;
	/* pathnames of lower and upper dirs, for show_options */
	struct ovl_config config;
	/* creds of process who forced instantiation of super block */
	const struct cred *creator_cred;
	bool tmpfile;
	bool noxattr;
	/* Did we take the inuse lock? */
	bool upperdir_locked;
	bool workdir_locked;
	bool share_whiteout;
	/* Traps in ovl inode cache */
	struct inode *workbasedir_trap;
	struct inode *workdir_trap;
	struct inode *indexdir_trap;
	/* -1: disabled, 0: same fs, 1..32: number of unused ino bits */
	int xino_mode;
	/* For allocation of non-persistent inode numbers */
	atomic_long_t last_ino;
	/* Whiteout dentry cache */
	struct dentry *whiteout;
	/* r/o snapshot of upperdir sb's only taken on volatile mounts */
	errseq_t errseq;
};

struct ovl_sb__new {
	struct super_block *sb;
	dev_t pseudo_dev;
	/* Unusable (conflicting) uuid */
	bool bad_uuid;
	/* Used as a lower layer (but maybe also as upper) */
	bool is_lower;
};

struct ovl_sb_old {
	struct super_block *sb;
	dev_t pseudo_dev;
	/* Unusable (conflicting) uuid */
	bool bad_uuid;
};

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
static inline __attribute__((always_inline)) dev_t
fix_dev_id_ovl(struct inode *inode, struct dentry *dentry, dev_t dev_id)
{
	struct super_block *sb;
	struct ovl_fs *s_fs_info;
	umode_t i_mode;
	unsigned long s_magic;

	probe_read(&sb, sizeof(sb), _(&dentry->d_sb));
	if (!sb)
		return dev_id;

	// we care only for inodes in overlayfs
	probe_read(&s_magic, sizeof(s_magic), _(&sb->s_magic));
	if (s_magic != OVERLAYFS_SUPER_MAGIC)
		return dev_id;

	probe_read(&s_fs_info, sizeof(s_fs_info), _(&sb->s_fs_info));

	if (bpf_core_field_exists(sb->s_wb_err)) { // introduced in 5.8
		struct ovl_fs__new pof;
		int xino_mode;
		unsigned int xinobits;
		bool samefs;

		probe_read(&pof, sizeof(pof), s_fs_info);
		xino_mode = pof.xino_mode;

		// all layers are over the same file system
		// no need to take any action
		samefs = xino_mode == 0;
		if (samefs)
			return dev_id;

		// xino is ON
		// no need to take any action
		xinobits = (xino_mode >= 0) ? xino_mode : 0;
		if (xinobits)
			return dev_id;
	} else {
		struct ovl_fs__old pof;
		unsigned int xino_bits;
		unsigned int numlowerfs;
		struct vfsmount *upper_mnt;

		probe_read(&pof, sizeof(pof), s_fs_info);

		numlowerfs = pof.numlowerfs;
		upper_mnt = pof.upper_mnt;
		if (!numlowerfs)
			return dev_id;
		else if (numlowerfs == 1 && !upper_mnt)
			return dev_id;

		xino_bits = pof.xino_bits;
		if (xino_bits)
			return dev_id;
	}

	// this is a directory
	// no need to take any action
	probe_read(&i_mode, sizeof(i_mode), _(&inode->i_mode));
	if (S_ISDIR(i_mode))
		return dev_id;

	if (bpf_core_field_exists(sb->s_wb_err)) { // introduced in 5.8
		struct ovl_fs__new pof;
		struct ovl_sb__new *pos, os;
		int fsid;

		probe_read(&pof, sizeof(pof), s_fs_info);

		fsid = ovl_layer_lower_fsid(dentry);
		asm volatile("%[fsid] &= 0xf;\n" ::[fsid] "+r"(fsid)
			     :);

		pos = (struct ovl_sb__new *)pof.fs;
		probe_read(&os, sizeof(os),
			   (char *)pos + (fsid * sizeof(struct ovl_sb__new)));
		return os.pseudo_dev;
	} else {
		struct ovl_layer *pol, ol;
		struct ovl_sb os;

		pol = ovl_layer_lower(dentry);
		if (!pol)
			return dev_id;

		probe_read(&ol, sizeof(ol), pol);
		probe_read(&os, sizeof(os), ol.fs);
		return os.pseudo_dev;
	}
}

static inline __attribute__((always_inline)) void
get_fs_info(struct msg_fs_info *msg, struct inode *inode, struct dentry *dentry)
{
	struct super_block *sb;
	struct file_system_type *sb_type;
	char *sb_name;

	probe_read(&sb, sizeof(sb), _(&inode->i_sb));
	if (!sb)
		return;

	probe_read(&(msg->dev), sizeof(msg->dev), _(&sb->s_dev));
	// fix dev_id for overlayfs (if needed)
	msg->dev = fix_dev_id_ovl(inode, dentry, msg->dev);
	msg->pad = 0;
	probe_read(msg->id, 8 * sizeof(char), _(&(sb->s_id[0])));

	probe_read(&sb_type, sizeof(sb_type), _(&sb->s_type));
	if (!sb_type)
		return;

	probe_read(&sb_name, sizeof(sb_name), _(&sb_type->name));
	if (!sb_name)
		return;

	probe_read_str(msg->name, 8 * sizeof(char), sb_name);
	probe_read(msg->uuid, 16 * sizeof(char), _(&sb->s_uuid));
}

static inline __attribute__((always_inline)) void
get_ino_fs(struct msg_file_ops *msg, struct inode *inode, struct dentry *dentry)
{
	probe_read(&(msg->ino), sizeof(msg->ino), _(&inode->i_ino));

	get_fs_info(&(msg->fs), inode, dentry);
}

static inline __attribute__((always_inline)) void
get_parent_ino_fs(struct msg_file_ops *msg, struct dentry *parent_dentry)
{
	struct inode *parent_inode;

	probe_read(&parent_inode, sizeof(parent_inode),
		   _(&parent_dentry->d_inode));
	if (!parent_inode)
		return;

	probe_read(&(msg->parent_ino), sizeof(msg->parent_ino),
		   _(&parent_inode->i_ino));

	get_fs_info(&(msg->parent_fs), parent_inode, parent_dentry);
}

static inline __attribute__((always_inline)) struct hash_map_file_val *
find_inode_in_map(struct bpf_map_def *inode_map, __u64 ino, __u32 dev)
{
	struct hash_map_file_key file_key;

	file_key.ino = ino;
	file_key.dev_major = MAJOR(dev);
	file_key.dev_minor = MINOR(dev);

	return map_lookup_elem(inode_map, &file_key);
}
