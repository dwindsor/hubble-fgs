#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all create operations.
 * Returns:
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int
block_file_create(void *ctx, struct inode *dir, struct dentry *dentry)
{
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	__u32 dlen_size = 0, dlen_offset = 0;
	__u32 dir_size = 0, dir_offset = 0;
	__u32 path_size = 0;
	int zero = 0, action = 0;
	struct qstr d_name;
	char *buffer;
	__u32 operation = 0;

	msg = get_msg_init();
	if (!msg)
		return -1;

	// get parent inode and fs info
	probe_read(&parent_dentry, sizeof(parent_dentry), _(&dentry->d_parent));
	if (!parent_dentry)
		return -1;

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
		return -1;

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
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	// although we care about files inside this directory
	// we may have this specific file path in the exclude
	// list now we check the trie with the initial paths
	key = map_lookup_elem(&lpm_trie_heap_key, &zero);
	if (!key)
		return -1;

	key->prefixlen = msg->path.size * 8;
	memcpy(key->data, msg->path.str, 256);

	action = filter_match(key);
	if (action == FILTER_NOTFOUND || action == FILTER_IGNORE || action == FILTER_MONITOR)
		return 0; // we don't care

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we also have to update any internal maps,
	// which is already done here.
	operation = eval_selectors(action_create);
	if (!(operation & FILE_OP_POST))
		return 0;

	msg->action = action_create;
	msg->hook = hook_security_inode_create;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;

	if (operation & FILE_OP_BLOCK) { // otherwise we will get the event after the actual create to have the inode info
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));
		return 1;
	}
	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(security_inode_create_lsm, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (block_file_create(ctx, dir, dentry) == 1)
		return -EPERM;
	return 0;
}

SEC("fmod_ret/security_inode_create")
int BPF_PROG(security_inode_create_fmod, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (block_file_create(ctx, dir, dentry) == 1)
		return -EPERM;
	return 0;
}
