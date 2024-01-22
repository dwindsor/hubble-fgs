#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/filemap_page_mkwrite")
int BPF_KPROBE(filemap_page_mkwrite, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	unsigned long flags;
	struct file *file;
	int err = 0;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma) {
		err = -FILE_ERR_VMA_FROM_VMF;
		goto filemap_page_mkwrite_error;
	}

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	if (!(flags & VM_SHARED)) // we care only for writes in shared mappings
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file) {
		err = -FILE_ERR_FILE_FROM_VMA;
		goto filemap_page_mkwrite_error;
	}

	err = handle_generic_file_access(ctx, file, action_write, hook_filemap_page_mkwrite);
	if (err < 0)
		goto filemap_page_mkwrite_error;

	return 0;

filemap_page_mkwrite_error:
	inc_error(hook_filemap_page_mkwrite, -err);
	return 0;
}
