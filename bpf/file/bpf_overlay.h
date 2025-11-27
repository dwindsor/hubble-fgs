#ifndef __OVERLAY_H__
#define __OVERLAY_H__

#include "vmlinux.h"
#include "vmlinux_overlay.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

static inline __attribute__((always_inline)) struct inode *d_inode(const struct dentry *dentry)
{
	return BPF_CORE_READ(dentry, d_inode);
}

static inline __attribute__((always_inline)) struct ovl_inode *OVL_I(struct inode *inode)
{
	return container_of_btf(inode, struct ovl_inode, vfs_inode);
}

struct ovl_inode___new {
	struct ovl_path lowerpath;
} __attribute__((preserve_access_index));

struct ovl_inode___new2 {
	struct ovl_entry *oe;
} __attribute__((preserve_access_index));

static inline struct ovl_entry *OVL_I_E(struct inode *inode)
{
	struct ovl_inode___new2 *oi_new = (void *)OVL_I(inode);
	return inode ? BPF_CORE_READ(oi_new, oe) : NULL;
}

static inline __attribute__((always_inline)) struct dentry *ovl_upperdentry_dereference(struct ovl_inode *oi)
{
	return BPF_CORE_READ(oi, __upperdentry);
}

static inline __attribute__((always_inline)) struct dentry *ovl_dentry_upper(struct dentry *dentry)
{
	return ovl_upperdentry_dereference(OVL_I(d_inode(dentry)));
}

static inline __attribute__((always_inline)) bool constant_test_bit(int nr, const void *addr)
{
	const u32 *p = (const u32 *)addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}

static inline __attribute__((always_inline)) bool ovl_test_flag(unsigned long flag, struct inode *inode)
{
	unsigned long flags = BPF_CORE_READ(OVL_I(inode), flags);
	return constant_test_bit(flag, &flags);
}

#define DCACHE_ENTRY_TYPE     0x00700000
#define DCACHE_DIRECTORY_TYPE 0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE   0x00300000 /* Lookupless directory (presumed automount) */

static inline __attribute__((always_inline)) unsigned __d_entry_type(const struct dentry *dentry)
{
	return BPF_CORE_READ(dentry, d_flags) & DCACHE_ENTRY_TYPE;
}

static inline __attribute__((always_inline)) bool d_can_lookup(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_DIRECTORY_TYPE;
}

static inline __attribute__((always_inline)) bool d_is_autodir(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_AUTODIR_TYPE;
}

static inline __attribute__((always_inline)) bool d_is_dir(const struct dentry *dentry)
{
	return d_can_lookup(dentry) || d_is_autodir(dentry);
}

struct ovl_entry___new {
	unsigned int __numlower;
	struct ovl_path __lowerstack[];
} __attribute__((preserve_access_index));

static inline unsigned int ovl_numlower(struct ovl_entry *oe)
{
	if (bpf_core_field_exists(oe->numlower))
		return BPF_CORE_READ(oe, numlower);
	else {
		struct ovl_entry___new *oe_new = (void *)oe;
		return BPF_CORE_READ(oe_new, __numlower);
	}
}

static inline struct ovl_path *ovl_lowerstack(struct ovl_entry *oe)
{
	if (bpf_core_field_exists(oe->lowerstack)) {
		return ovl_numlower(oe) ? oe->lowerstack : NULL;
	} else {
		struct ovl_entry___new *oe_new = (void *)oe;
		return ovl_numlower(oe) ? oe_new->__lowerstack : NULL;
	}
}

static inline struct ovl_path *ovl_lowerpath(struct ovl_entry *oe)
{
	return ovl_lowerstack(oe);
}

static inline __attribute__((always_inline)) struct inode *ovl_inode_lower(struct inode *inode)
{
	struct ovl_inode *oi = OVL_I(inode);
	struct ovl_inode___new *oi_new = (void *)oi;

	if (bpf_core_field_exists(oi->lower)) {
		return BPF_CORE_READ(oi, lower);
	} else if (bpf_core_field_exists(oi_new->lowerpath)) {
		struct dentry *lowerdentry = BPF_CORE_READ(oi_new, lowerpath.dentry);
		return lowerdentry ? d_inode(lowerdentry) : NULL;
	} else {
		struct ovl_path *lowerpath = ovl_lowerpath(OVL_I_E(inode));
		return lowerpath ? d_inode(BPF_CORE_READ(lowerpath, dentry)) : NULL;
	}
}

#define OS_IFMT	 00170000
#define OS_IFREG 0100000
#define OS_IFDIR 0040000

#define OS_ISREG(m) (((m) & OS_IFMT) == OS_IFREG)
#define OS_ISDIR(m) (((m) & OS_IFMT) == OS_IFDIR)

static inline __attribute__((always_inline)) bool ovl_should_check_upperdata(struct inode *inode)
{
	umode_t mode = BPF_CORE_READ(inode, i_mode);
	if (!OS_ISREG(mode))
		return false;

	if (!ovl_inode_lower(inode))
		return false;

	return true;
}

static inline __attribute__((always_inline)) bool ovl_has_upperdata(struct inode *inode)
{
	if (!ovl_should_check_upperdata(inode))
		return true;

	if (!ovl_test_flag(OVL_UPPERDATA, inode))
		return false;
	/*
	 * Pairs with smp_wmb() in ovl_set_upperdata(). Main user of
	 * ovl_has_upperdata() is ovl_copy_up_meta_inode_data(). Make sure
	 * if setting of OVL_UPPERDATA is visible, then effects of writes
	 * before that are visible too.
	 */
	__asm__ __volatile__(""
			     :
			     :
			     : "memory");
	return true;
}

static inline __attribute__((always_inline)) enum ovl_path_type ovl_path_type(struct dentry *dentry)
{
	enum ovl_path_type type = 0;
	struct ovl_entry *oe = 0;
	unsigned numlower = 0;

	oe = BPF_CORE_READ(dentry, d_fsdata);

	if (bpf_core_field_exists(oe->numlower))
		numlower = BPF_CORE_READ(oe, numlower);
	else {
		struct ovl_entry___new *oe_new = (void *)oe;
		numlower = BPF_CORE_READ(oe_new, __numlower);
	}

	if (ovl_dentry_upper(dentry)) {
		type = __OVL_PATH_UPPER;

		/*
		 * Non-dir dentry can hold lower dentry of its copy up origin.
		 */
		if (numlower) {
			if (ovl_test_flag(OVL_CONST_INO, d_inode(dentry)))
				type |= __OVL_PATH_ORIGIN;
			if (d_is_dir(dentry) || !ovl_has_upperdata(d_inode(dentry)))
				type |= __OVL_PATH_MERGE;
		}
	} else {
		if (numlower > 1)
			type |= __OVL_PATH_MERGE;
	}
	return type;
}

#define OVL_TYPE_UPPER(type)  ((type) & __OVL_PATH_UPPER)
#define OVL_TYPE_MERGE(type)  ((type) & __OVL_PATH_MERGE)
#define OVL_TYPE_ORIGIN(type) ((type) & __OVL_PATH_ORIGIN)

static inline __attribute__((always_inline)) void ovl_path_lower(struct dentry *dentry, struct path *path)
{
	struct ovl_entry *oe = BPF_CORE_READ(dentry, d_fsdata);
	unsigned numlower = 0;

	if (bpf_core_field_exists(oe->numlower)) {
		numlower = BPF_CORE_READ(oe, numlower);
	} else {
		struct ovl_entry___new *oe_new = (void *)oe;
		numlower = BPF_CORE_READ(oe_new, __numlower);
	}

	if (numlower) {
		if (bpf_core_field_exists(oe->lowerstack)) {
			path->mnt = BPF_CORE_READ(oe, lowerstack[0].layer, mnt);
			path->dentry = BPF_CORE_READ(oe, lowerstack[0].dentry);
		} else {
			struct ovl_entry___new *oe_new = (void *)oe;
			path->mnt = BPF_CORE_READ(oe_new, __lowerstack[0].layer, mnt);
			path->dentry = BPF_CORE_READ(oe_new, __lowerstack[0].dentry);
		}
	} else {
		*path = (struct path){};
	}
}

static inline __attribute__((always_inline)) struct vfsmount *ovl_upper_mnt(struct ovl_fs *ofs)
{
	return BPF_CORE_READ(ofs, layers, mnt); // ofs->layers[0].mnt;
}

static inline __attribute__((always_inline)) void ovl_path_upper(struct dentry *dentry, struct path *path)
{
	struct ovl_fs *ofs = BPF_CORE_READ(dentry, d_sb, s_fs_info);

	path->mnt = ovl_upper_mnt(ofs);
	path->dentry = ovl_dentry_upper(dentry);
}

static inline __attribute__((always_inline)) enum ovl_path_type ovl_path_real(struct dentry *dentry, struct path *path)
{
	enum ovl_path_type type = ovl_path_type(dentry);

	if (!OVL_TYPE_UPPER(type))
		ovl_path_lower(dentry, path);
	else
		ovl_path_upper(dentry, path);

	return type;
}

static inline __attribute__((always_inline))
const struct ovl_layer *
ovl_layer_lower(struct dentry *dentry)
{
	struct ovl_entry *oe = BPF_CORE_READ(dentry, d_fsdata);
	unsigned numlower = 0;

	if (bpf_core_field_exists(oe->numlower))
		numlower = BPF_CORE_READ(oe, numlower);
	else {
		struct ovl_entry___new *oe_new = (void *)oe;
		numlower = BPF_CORE_READ(oe_new, __numlower);
	}

	if (bpf_core_field_exists(oe->lowerstack)) {
		return numlower ? BPF_CORE_READ(oe, lowerstack[0].layer) : NULL;
	} else {
		struct ovl_entry___new *oe_new = (void *)oe;
		return numlower ? BPF_CORE_READ(oe_new, __lowerstack[0].layer) : NULL;
	}
}

static inline __attribute__((always_inline)) struct ovl_fs *OVL_FS(struct super_block *sb)
{
	struct ovl_fs *ofs = BPF_CORE_READ(sb, s_fs_info);
	return ofs;
}

static inline __attribute__((always_inline)) bool ovl_same_fs(struct super_block *sb)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	return BPF_CORE_READ(ofs, xino_mode) == 0;
}

static inline __attribute__((always_inline)) bool ovl_same_dev(struct super_block *sb)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	return BPF_CORE_READ(ofs, xino_mode) >= 0;
}

static inline __attribute__((always_inline)) unsigned int ovl_xino_bits(struct super_block *sb)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	return ovl_same_dev(sb) ? BPF_CORE_READ(ofs, xino_mode) : 0;
}

static inline __attribute__((always_inline)) void ovl_map_dev_ino(struct dentry *dentry, struct ovl_kstat *stat, int fsid)
{
	struct super_block *sb = BPF_CORE_READ(dentry, d_sb);
	bool samefs = ovl_same_fs(sb);
	unsigned int xinobits = ovl_xino_bits(sb);
	unsigned int xinoshift = 64 - xinobits;

	if (samefs) {
		/*
		 * When all layers are on the same fs, all real inode
		 * number are unique, so we use the overlay st_dev,
		 * which is friendly to du -x.
		 */
		stat->dev = BPF_CORE_READ(sb, s_dev);
		return;
	} else if (xinobits) {
		/*
		 * All inode numbers of underlying fs should not be using the
		 * high xinobits, so we use high xinobits to partition the
		 * overlay st_ino address space. The high bits holds the fsid
		 * (upper fsid is 0). The lowest xinobit is reserved for mapping
		 * the non-persistent inode numbers range in case of overflow.
		 * This way all overlay inode numbers are unique and use the
		 * overlay st_dev.
		 */
		if (likely(!(stat->ino >> xinoshift))) {
			stat->ino |= ((u64)fsid) << (xinoshift + 1);
			stat->dev = BPF_CORE_READ(dentry, d_sb, s_dev);
			return;
		}
		// else if (ovl_xino_warn(dentry->d_sb)) {
		//	pr_warn_ratelimited("inode number too big (%pd2, ino=%llu, xinobits=%d)\n",
		//			    dentry, stat->ino, xinobits);
		// }
	}

	/* The inode could not be mapped to a unified st_ino address space */
	if (OS_ISDIR(BPF_CORE_READ(dentry, d_inode, i_mode))) {
		/*
		 * Always use the overlay st_dev for directories, so 'find
		 * -xdev' will scan the entire overlay mount and won't cross the
		 * overlay mount boundaries.
		 *
		 * If not all layers are on the same fs the pair {real st_ino;
		 * overlay st_dev} is not unique, so use the non persistent
		 * overlay st_ino for directories.
		 */
		stat->dev = BPF_CORE_READ(sb, s_dev);
		stat->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	} else {
		/*
		 * For non-samefs setup, if we cannot map all layers st_ino
		 * to a unified address space, we need to make sure that st_dev
		 * is unique per underlying fs, so we use the unique anonymous
		 * bdev assigned to the underlying fs.
		 */
		struct ovl_sb *fs = BPF_CORE_READ(OVL_FS(sb), fs);
		asm volatile("%[fsid] &= 0xf;\n"
			     : [fsid] "+r"(fsid));
		fs += fsid;
		stat->dev = BPF_CORE_READ(fs, pseudo_dev);
	}
}

static inline __attribute__((always_inline)) bool ovl_verify_lower(struct super_block *sb)
{
	struct ovl_fs *ofs = BPF_CORE_READ(sb, s_fs_info);

	return BPF_CORE_READ(ofs, config.nfs_export) && BPF_CORE_READ(ofs, config.index);
}

static inline __attribute__((always_inline)) void ovl_getattr(struct inode *inode, struct dentry *dentry, __u64 *ino, __u32 *dev)
{
	enum ovl_path_type type;
	struct path realpath;
	struct ovl_kstat stat = { 0 };
	bool is_dir;
	int fsid = 0;

	stat.ino = BPF_CORE_READ(inode, i_ino);
	stat.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	is_dir = OS_ISDIR(BPF_CORE_READ(inode, i_mode));
	type = ovl_path_real(dentry, &realpath);

	/*
	 * For non-dir or same fs, we use st_ino of the copy up origin.
	 * This guaranties constant st_dev/st_ino across copy up.
	 * With xino feature and non-samefs, we use st_ino of the copy up
	 * origin masked with high bits that represent the layer id.
	 *
	 * If lower filesystem supports NFS file handles, this also guaranties
	 * persistent st_ino across mount cycle.
	 */
	if (!is_dir || ovl_same_dev(BPF_CORE_READ(dentry, d_sb))) {
		if (!OVL_TYPE_UPPER(type)) {
			fsid = BPF_CORE_READ(ovl_layer_lower(dentry), fsid);
		} else if (OVL_TYPE_ORIGIN(type)) {
			ovl_path_lower(dentry, &realpath);

			/*
			 * Lower hardlinks may be broken on copy up to different
			 * upper files, so we cannot use the lower origin st_ino
			 * for those different files, even for the same fs case.
			 *
			 * Similarly, several redirected dirs can point to the
			 * same dir on a lower layer. With the "verify_lower"
			 * feature, we do not use the lower origin st_ino, if
			 * we haven't verified that this redirect is unique.
			 *
			 * With inodes index enabled, it is safe to use st_ino
			 * of an indexed origin. The index validates that the
			 * upper hardlink is not broken and that a redirected
			 * dir is the only redirect to that origin.
			 */
			if (ovl_test_flag(OVL_INDEX, d_inode(dentry)) || (!ovl_verify_lower(BPF_CORE_READ(dentry, d_sb)) && (is_dir || BPF_CORE_READ(realpath.dentry, d_inode, i_nlink) == 1))) {
				fsid = BPF_CORE_READ(ovl_layer_lower(dentry), fsid);
				stat.ino = BPF_CORE_READ(realpath.dentry, d_inode, i_ino);
			}
		}
	}

	ovl_map_dev_ino(dentry, &stat, fsid);

	if (stat.ino)
		*ino = stat.ino;
	if (stat.dev)
		*dev = stat.dev;
}

#endif /* __OVERLAY_H__ */
