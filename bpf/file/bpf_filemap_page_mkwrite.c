#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/filemap_page_mkwrite"), used)) int
BPF_KPROBE(filemap_page_mkwrite, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	__u32 pgoff;
	struct file *file;

	probe_read(&pgoff, sizeof(pgoff), _(&vmf->pgoff));

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	return handle_generic_file_write(ctx, file, hook_filemap_page_mkwrite,
					 pgoff * PAGE_SIZE,
					 (pgoff + 1) * PAGE_SIZE);
}
