#include "bpf_file.h"
#include "generic_file_access.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/filemap_page_mkwrite")
int BPF_KPROBE(filemap_page_mkwrite, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	struct file *file;

	probe_read(&vma, sizeof(vma), _(&vmf->vma));
	if (!vma)
		return 0;

	probe_read(&file, sizeof(file), _(&vma->vm_file));
	if (!file)
		return 0;

	handle_generic_file_access(ctx, file, action_write, hook_filemap_page_mkwrite);

	return 0;
}
