#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/filemap_fault"), used)) int
BPF_KPROBE(filemap_fault, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	struct file *file;
	unsigned long flags;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// if we have a write page-fault we also issue a read event
	// as it may happen without any page faults or other actions
	if (flags & VM_WRITE) {
		handle_generic_file_access(ctx, file, action_write, hook_filemap_fault);
	}
	handle_generic_file_access(ctx, file, action_read, hook_filemap_fault);

	return 0;
}
