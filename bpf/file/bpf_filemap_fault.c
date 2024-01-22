#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/filemap_fault")
int BPF_KPROBE(filemap_fault, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	struct file *file;
	unsigned long flags;
	int err = 0;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma) {
		err = -FILE_ERR_VMA_FROM_VMF;
		goto hook_filemap_fault_error;
	}

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0; // this not really an error, it can be a non-file-backed mapping

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	err = handle_generic_file_access(ctx, file, action_read, hook_filemap_fault);
	if (err < 0)
		goto hook_filemap_fault_error;

	// if we have a write page-fault we also issue a read event
	// as it may happen without any page faults or other actions
	if ((flags & VM_WRITE) && (flags & VM_SHARED)) { // we care only for writes in shared mappings
		err = handle_generic_file_access(ctx, file, action_write, hook_filemap_fault);
		if (err < 0)
			goto hook_filemap_fault_error;
	}

	return 0;

hook_filemap_fault_error:
	inc_error(hook_filemap_fault, -err);
	return 0;
}
