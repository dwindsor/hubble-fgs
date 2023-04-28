#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "hubble_msg.h"
#include "bpf_events.h"

#include "file.h"
#include "iso_msg_types.h"
#include "bpf_process_event.h"
#include "types/operations.h"

#define FILTER_NOTFOUND -1
#define FILTER_IGNORE	0
#define FILTER_MATCH	1

/* generic data direction definitions */
#define READ  0
#define WRITE 1

#define MAY_WRITE 0x00000002
#define MAY_READ  0x00000004

#define FAULT_FLAG_WRITE   0x01
#define FAULT_FLAG_MKWRITE 0x02

#define VM_READ	 0x00000001
#define VM_WRITE 0x00000002

#define FMODE_CREATED 0x100000

#define PAGE_SIZE 4096

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct retprobe_key);
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
	__type(key, struct retprobe_key);
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

struct lpm_data {
	struct bpf_lpm_trie_key key;
	char data[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_data);
	__type(value, uint32_t);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_trie_map_alloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct lpm_data);
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

/*
 * For matchBinaries we use two maps:
 * 1. names_map: global (for all sensors) keeps a mapping from names -> ids
 * 2. sel_names_map: per-sensor: keeps a mapping from id -> selector val
 *
 * At exec time, we check names_map and set ->binary in execve_map equal to
 * the id stored in names_map. Assuming the binary name exists in the map,
 * otherwise binary is 0.
 *
 * When we check the selectors, use ->binary to index sel_names_map and decide
 * whether the selector matches or not.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} file_names_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} file_ops_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_config_map_value);
} file_config_map SEC(".maps");

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_binaries()
{
	__u32 max = 0xffffffff; // UINT32_MAX
	__u32 *op;

	op = map_lookup_elem(&file_names_map, &max);
	if (op) {
		struct execve_map_value *execve;
		bool walker = 0;
		__u32 ppid, bin_key, *bin_val;

		execve = event_find_curr(&ppid, &walker);
		if (!execve)
			return 0;

		bin_key = execve->binary;
		bin_val = map_lookup_elem(&file_names_map, &bin_key);

		/*
		 * The following things may happen:
		 * binary is not part of names_map, execve_map->binary will be `0` and `bin_val` will always be `0`
		 * binary is part of `names_map`:
		 *  if binary is not part of this selector, bin_val will be`0`
		 *  if binary is part of this selector: `bin_val will be `!0`
		 */
		if (*op == op_filter_in) {
			if (!bin_val)
				return 0;
		} else if (*op == op_filter_notin) {
			if (bin_val)
				return 0;
		}

		return 1;
	}

	// If 'max' not found in file_names_map this means that we don't have any
	// matchBinaries selectors.
	return 1;
}

// returns 1 if it matches, 0 otherwise
static inline __attribute__((always_inline)) int check_match_operations(__u32 action)
{
	__u32 max = 0xffffffff; // UINT32_MAX
	__u32 *op, *val;

	op = map_lookup_elem(&file_ops_map, &max);
	if (op) {
		val = map_lookup_elem(&file_ops_map, &action);
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
static inline __attribute__((always_inline)) int check_enforcement()
{
	__u32 zero = 0;
	struct file_config_map_value *conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return 0;
	return (conf->action_value & FILE_OP_BLOCK) != 0;
}

static inline __attribute__((always_inline)) __u32
eval_selectors(__u32 action)
{
	if (!check_match_binaries())
		goto nopost;
	if (!check_match_operations(action))
		goto nopost;
	if (!check_enforcement())
		goto post;

	return FILE_OP_POST | FILE_OP_BLOCK;
post:
	return FILE_OP_POST;
nopost:
	return 0;
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
filter_match(struct bpf_lpm_trie_key *key)
{
	uint32_t *retval = map_lookup_elem(&lpm_trie_map_alloc, key);
	if (retval)
		return *retval;
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

static inline __attribute__((always_inline)) int
check_file_create(struct pt_regs *ctx, struct file *f, struct inode *inode,
		  struct path *path, __u32 hook)
{
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_key file_key;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 f_mode, path_size = 0;
	int zero = 0, action = 0;
	struct qstr d_name;
	char *buffer;
	__u32 operation = 0;

	probe_read(&f_mode, sizeof(f_mode), _(&f->f_mode));
	if ((f_mode & FMODE_CREATED) == 0)
		return 0; // no file created

	msg = get_msg_init();
	if (!msg)
		return 0;

	// get current inode and fs info
	probe_read(&dentry, sizeof(struct dentry *), _(&path->dentry));
	get_ino_fs(msg, inode, dentry);

	// get parent inode and fs info
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// find the parent directory entry
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_dir_alloc,
				     msg->parent_ino, msg->parent_fs.dev);
	if (!file_val)
		return 0;
	// we don't care for anything inside this directory
	if (file_val->action == FILTER_IGNORE)
		return 0;

	// we care about files inside this directory
	// get a buffer to generate its path
	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	// first write the dentry name
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size)
		     :);
	dlen_offset = MAX_FILEPATH_SIZE;
	probe_read(buffer + dlen_offset, dlen_size, (const char *)d_name.name);
	path_size += dlen_size;

	// then write the directory name
	// this is what we have in the map already (we don't traverse anything)
	dir_size = file_val->size;
	asm volatile("%[dir_size] &= 0xff;\n" ::[dir_size] "+r"(dir_size)
		     :);
	dir_offset = MAX_FILEPATH_SIZE - dir_size;
	asm volatile("%[dir_offset] &= 0xff;\n" ::[dir_offset] "+r"(dir_offset)
		     :);
	probe_read(buffer + dir_offset, dir_size, file_val->path);
	path_size += dir_size;

	// set the filepath inside msg
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(msg->path.str, path_size, buffer + dir_offset);
	msg->path.size = path_size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE) {
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	}
	msg->path.flags |= file_val->location_flags;

	// although we care about files inside this directory
	// we may have this specific file path in the exclude
	// list now we check the trie with the initial paths
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return 0;

	key->prefixlen = msg->path.size * 8;
	memcpy(key->data, msg->path.str, 256);

	action = filter_match(key);
	if (action == FILTER_NOTFOUND || action == FILTER_IGNORE)
		return 0; // we don't care

	// and insert that inode to the hash_map_file_alloc
	file_key.ino = msg->ino;
	file_key.dev_major = MAJOR(msg->fs.dev);
	file_key.dev_minor = MINOR(msg->fs.dev);

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	file_val->action = action;
	file_val->size = msg->path.size;
	asm volatile("%[path_size] &= 0xff;\n" ::[path_size] "+r"(path_size)
		     :);
	probe_read(file_val->path, path_size, msg->path.str);

	if (msg->path.flags & CONTAINER_FILE) {
		file_val->location_flags = CONTAINER_FILE;
		memcpy(file_val->container_id, msg->path.container_id, CONTAINER_ID_LEN);
	} else {
		file_val->location_flags = HOST_FILE;
	}

	// add this new file to the map of files
	map_update_elem(&hash_map_file_alloc, &file_key, file_val, 0);

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_create);
	if (!(operation & FILE_OP_POST))
		return 0;

	probe_read(&(msg->imode[0]), sizeof(msg->imode[0]), _(&inode->i_mode));
	probe_read(&(msg->uid[0]), sizeof(msg->uid[0]), _(&inode->i_uid));
	probe_read(&(msg->gid[0]), sizeof(msg->gid[0]), _(&inode->i_gid));

	msg->action = action_create;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_ops));

	return 0;
}
