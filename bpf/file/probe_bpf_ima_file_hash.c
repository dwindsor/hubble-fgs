#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct inode_key);
	__type(value, struct digest_key);
	__uint(max_entries, 1);
} probe_digests_map SEC(".maps");

SEC("lsm.s/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm)
{
	__u32 dev = BPF_CORE_READ(bprm, file, f_inode, i_sb, s_dev);
	struct inode_key key = {
		.ino = BPF_CORE_READ(bprm, file, f_inode, i_ino),
		.dev_major = MAJOR(dev),
		.dev_minor = MINOR(dev),
	};
	struct digest_key *val = 0;

	val = map_lookup_elem(&probe_digests_map, &key);
	if (!val)
		return 0;

	val->ok = 1;
	val->algo = ima_file_hash(_(bprm->file), val->digest, IMA_MAX_DIGEST_SIZE);

	return 0;
}
