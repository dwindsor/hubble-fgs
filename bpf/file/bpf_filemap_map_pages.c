#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/filemap_map_pages"), used)) int
BPF_KPROBE(filemap_map_pages, struct vm_fault *vmf, __u32 start_pgoff,
	   __u32 end_pgoff)
{
	struct vm_area_struct *vma;
	unsigned long flags;
	struct file *file;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	probe_read(&flags, sizeof(flags), _(&vma->vm_flags));

	// generate both events as after a write pgfault we can read
	if (flags & VM_WRITE) {
		handle_generic_file_write(ctx, file, hook_filemap_map_pages,
					  start_pgoff * PAGE_SIZE,
					  (end_pgoff * PAGE_SIZE) + PAGE_SIZE);
	}
	handle_generic_file_read(ctx, file, hook_filemap_map_pages,
				 start_pgoff * PAGE_SIZE,
				 (end_pgoff * PAGE_SIZE) + PAGE_SIZE);

	return 0;
}
