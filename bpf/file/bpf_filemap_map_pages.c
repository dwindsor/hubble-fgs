#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/filemap_map_pages")
int BPF_KPROBE(filemap_map_pages, struct vm_fault *vmf, __u32 start_pgoff,
	       __u32 end_pgoff)
{
	struct vm_area_struct *vma;
	unsigned long flags;
	struct file *file;
	int err = 0;

	probe_read_kernel(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma) {
		err = -FILE_ERR_VMA_FROM_VMF;
		goto filemap_map_pages_error;
	}

	probe_read_kernel(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0; // this not really an error, it can be a non-file-backed mapping

	probe_read_kernel(&flags, sizeof(flags), _(&vma->vm_flags));

	err = handle_generic_file_access(ctx, file, action_read, hook_filemap_map_pages);
	if (err < 0)
		goto filemap_map_pages_error;

	// generate both events as after a write pgfault we can read
	if ((flags & VM_WRITE) && (flags & VM_SHARED)) { // we care only for writes in shared mappings
		err = handle_generic_file_access(ctx, file, action_write, hook_filemap_map_pages);
		if (err < 0)
			goto filemap_map_pages_error;
	}

	return 0;

filemap_map_pages_error:
	inc_error(hook_filemap_map_pages, -err);
	return 0;
}
