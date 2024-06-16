//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	mapHelpers "maps"
	"net/rpc"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/grpc/file"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"

	"github.com/google/uuid"
)

const (
	overlayModName = "overlay"
	btfPath        = "/sys/kernel/btf/"
)

var (
	// We check for struct ovl_entry in the BTF and set this variable.
	hasOverlaySymbols = false

	// We check if /sys/kernel/btf/overlay exists and then we use it to
	// load it's symbols. If hasOverlaySymbols is false and hasOverlayBTF
	// is false, FIM works without support for overlayfs.
	hasOverlayBTF = false
)

type Mode uint32

const (
	Observe Mode = iota
	EnforceNotSupported
	EnforceFmodRet
	EnforceLSM
)

var fsScannerCmd *exec.Cmd
var fsScannerCancelFn context.CancelFunc
var fsScannerCancelFnMtx sync.Mutex

type FimFunc struct {
	proto, progName, progSection string
}

type FimHook struct {
	tp, name string
	prog     []FimFunc
}

type FimProg struct {
	tp, name, progName, progSection string
}

var (
	FimHooksObserve = [...]FimHook{
		{"kprobe", "vfs_fallocate", []FimFunc{{"vfs_fallocate(struct file*, int, loff_t, loff_t)", "bpf_vfs_fallocate.o", "vfs_fallocate"}}},
		{"kprobe", "filemap_fault", []FimFunc{{"filemap_fault(struct vm_fault*)", "bpf_filemap_fault.o", "filemap_fault"}}},
		{"kprobe", "filemap_map_pages", []FimFunc{{"filemap_map_pages(struct vm_fault*, int, int)", "bpf_filemap_map_pages.o", "filemap_map_pages"}}},
		{"kprobe", "filemap_page_mkwrite", []FimFunc{{"filemap_page_mkwrite(struct vm_fault*)", "bpf_filemap_page_mkwrite.o", "filemap_page_mkwrite"}}},
		{"kprobe", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission.o", "security_file_permission"}}},
		{"kprobe", "vfs_unlink", []FimFunc{
			{"vfs_unlink(struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/419"},
			{"vfs_unlink(struct user_namespace*, struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/512"},
			{"vfs_unlink(struct mnt_idmap*, struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/63"},
		}},
		{"kprobe", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir.o", "security_inode_rmdir"}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512"},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
		}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419"},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512"},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename"},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename"},
		}},
		{"kprobe", "iterate_dir", []FimFunc{{"iterate_dir(struct file*, struct dir_context*)", "bpf_iterate_dir.o", "iterate_dir"}}},
		{"kprobe", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/419"},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/60"},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/63"},
		}},
		{"kprobe", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link.o", "security_inode_link"}}},
		{"kprobe", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open.o", "security_file_open"}}},
	}

	FimHooksObserveExec = FimHook{"kprobe", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check.o", "security_bprm_check"}}}

	FimHooksFmodRet = [...]FimHook{
		{"fmod_ret", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_fmod.o", "security_mmap_file"}}},
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_fmod.o", "security_file_permission"}}},
		{"fmod_ret", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_fmod.o", "security_inode_unlink"}}},
		{"fmod_ret", "security_inode_create", []FimFunc{{"security_inode_create(struct inode*, struct dentry*, umode_t)", "bpf_security_inode_create_fmod.o", "security_inode_create"}}},
		{"fmod_ret", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir_enforce_fmod.o", "security_inode_rmdir"}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512"},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
		}},
		{"fmod_ret", "security_inode_mkdir", []FimFunc{{"security_inode_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir_enforce_fmod.o", "security_inode_mkdir"}}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419"},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512"},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename"},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename"},
		}},
		{"fmod_ret", "security_inode_rename", []FimFunc{{"security_inode_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, int)", "bpf_vfs_rename_enforce_fmod.o", "security_inode_rename"}}},
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_iterate_dir_enforce_fmod.o", "security_file_permission"}}},
		{"fmod_ret", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod.o", "security_inode_setattr"},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod_v60.o", "security_inode_setattr"},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod_v63.o", "security_inode_setattr"},
		}},
		{"fmod_ret", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link_enforce_fmod.o", "security_inode_link"}}},
		{"fmod_ret", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open_enforce_fmod.o", "security_file_open"}}},
	}

	FimHooksFmodRetExec = FimHook{"fmod_ret", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_fmod.o", "security_bprm_check"}}}

	FimHooksLsm = [...]FimHook{
		{"lsm", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_lsm.o", "mmap_file"}}},
		{"lsm", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_lsm.o", "file_permission"}}},
		{"lsm", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_lsm.o", "inode_unlink"}}},
		{"lsm", "security_inode_create", []FimFunc{{"security_inode_create(struct inode*, struct dentry*, umode_t)", "bpf_security_inode_create_lsm.o", "inode_create"}}},
		{"lsm", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir_enforce_lsm.o", "inode_rmdir"}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512"},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
		}},
		{"lsm", "security_inode_mkdir", []FimFunc{{"security_inode_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir_enforce_lsm.o", "inode_mkdir"}}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename"}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419"},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512"},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename"},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename"},
		}},
		{"lsm", "security_inode_rename", []FimFunc{{"security_inode_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, int)", "bpf_vfs_rename_enforce_lsm.o", "inode_rename"}}},
		{"lsm", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_iterate_dir_enforce_lsm.o", "file_permission"}}},
		{"lsm", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr"},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr"},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr"},
		}},
		{"lsm", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link_enforce_lsm.o", "inode_link"}}},
		{"lsm", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open_enforce_lsm.o", "file_open"}}},
	}

	FimHooksLsmExec = FimHook{"lsm", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm.o", "bprm_check_security"}}}

	FimHooksLsmExecDigests = [...]FimHook{
		{"lsm.s", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm_digest.o", "bprm_check_security"}}},
		{"fexit", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm_digest.o", "security_bprm_check"}}},
	}

	FileExecHooksLsmDigests = [...]FimHook{
		{"lsm.s", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_file_exec.o", "bprm_check_security"}}},
		{"fexit", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_file_exec.o", "security_bprm_check"}}},
	}

	FimIoUringHooks = [...]FimHook{
		{"kprobe", "io_read", []FimFunc{
			{"io_read(struct io_kiocb*, int)", "bpf_io_uring.o", "io_read/510"},
			{"io_read(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_read/59"},
			{"io_read(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_read/57"},
			{"io_read(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_read/55"},
			{"io_read(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_read/51"},
		}},
		{"kretprobe", "io_read", []FimFunc{
			{"int io_read(struct io_kiocb*, int)", "bpf_io_uring.o", "io_read"},
			{"int io_read(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_read"},
			{"int io_read(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_read"},
			{"int io_read(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_read"},
			{"int io_read(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_read"},
		}},
		{"kprobe", "io_write", []FimFunc{
			{"io_write(struct io_kiocb*, int)", "bpf_io_uring.o", "io_write/510"},
			{"io_write(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_write/59"},
			{"io_write(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_write/57"},
			{"io_write(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_write/55"},
			{"io_write(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_write/51"},
		}},
		{"kretprobe", "io_write", []FimFunc{
			{"int io_write(struct io_kiocb*, int)", "bpf_io_uring.o", "io_write"},
			{"int io_write(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_write"},
			{"int io_write(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_write"},
			{"int io_write(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_write"},
			{"int io_write(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_write"},
		}},
	}

	FimIoUringSingleHooks = [...]FimHook{
		{"kprobe", "io_issue_sqe", []FimFunc{{"io_issue_sqe(struct io_kiocb*, int)", "bpf_io_uring.o", "io_issue_sqe"}}},
		{"kretprobe", "io_issue_sqe", []FimFunc{{"int io_issue_sqe(struct io_kiocb*, int)", "bpf_io_uring.o", "io_issue_sqe"}}},
	}

	FimHooksFileCreate = [...]FimHook{
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
	}

	FimHooksFileCreate418 = [...]FimHook{
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*), int*)", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
		{"kprobe", "fsnotify", []FimFunc{{"fsnotify(struct inode*, __u32, const void*, int, const struct qstr*, u32)", "bpf_fsnotify.o", "fsnotify"}}},
	}

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"rename_retprobe_map",
		"spr_retprobe_map",
		"vr_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_inode_alloc",
		"tg_mb_sel_opts",
		"tg_mb_paths",
		"file_ops_maps",
		"file_namespaces_map",
		"file_capabilities_map",
		"file_digests_maps",
		"file_actions_map",
		"file_config_map",
		"file_errors_map",
	}
)

func TerminateFsScanner() error {
	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCTerminate)
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.Terminate", struct{}{}, &struct{}{}); err != nil {
		return err
	}

	// wait for fifo to be removed
	retry := 0
	for {
		if _, err := os.Stat(fm.ScannerFifoPath); err != nil {
			break
		}
		if retry > 10 {
			logger.GetLogger().Warnf("Failed to wait for fifo to be removed")
			break
		}
		time.Sleep(time.Second)
		retry++
	}

	fsScannerCmd = nil

	return killFsScanner() // to cleanup leftovers in the case of failures
}

func TracingPolicyInitFsScanner(tpName string, s v1alpha1.FileSpec, m string, pin string, addToMaps bool) (map[fileapi.InodeKey]fileapi.InodeVal, error) {
	f := fm.FsScannerInit{
		PolicyName: tpName,
		Spec:       s,
		MapDir:     m,
		PinPath:    pin,
		AddToMaps:  addToMaps,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitHost)
		return nil, err
	}
	defer client.Close()

	reply := make(map[fileapi.InodeKey]fileapi.InodeVal)
	if err := client.Call("FsScannerRpc.TracingPolicyInit", &f, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func RenameFsScanner(path, mapDir, pinPath, cId, polName string, spec v1alpha1.FileSpec, flags uint32) error {
	f := fm.FsScannerRename{
		WalkPath:    path,
		MapDir:      mapDir,
		PinPath:     pinPath,
		ContainerID: cId,
		Spec:        spec,
		PolicyName:  polName,
		Flags:       flags,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCScanner)
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.RenameDir", &f, &struct{}{})
}

func TracingPolicyInitContainerFsScanner(specPath []fm.SpecPinPath, containerID, podNs, podName, rootDir string, addToMaps bool) (map[fileapi.InodeKey]fileapi.InodeVal, error) {
	if len(specPath) == 0 {
		specPath = pol.FileMonitoringTable.GetValuesFIM()
	}
	f := fm.FsScannerContainerInit{
		Tp:          specPath,
		MapDir:      option.Config.BpfDir,
		ContainerID: containerID,
		PodNs:       podNs,
		PodName:     podName,
		RootDir:     rootDir,
		AddToMaps:   addToMaps,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitCont)
		return nil, err
	}
	defer client.Close()

	reply := make(map[fileapi.InodeKey]fileapi.InodeVal)
	if err := client.Call("FsScannerRpc.TracingPolicyContainerInit", &f, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func TracingPolicyDestroyContainerFsScanner(containerID string) error {
	specPath := pol.FileMonitoringTable.GetValuesFIM()
	f := fm.FsScannerContainerDestroy{
		Tp:          specPath,
		MapDir:      option.Config.BpfDir,
		ContainerID: containerID,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCDestroyCont)
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.TracingPolicyContainerDestroy", &f, &struct{}{})
}

func checkRunningFsScanner(scannerFifo string) error {
	matches, err := filepath.Glob("/proc/*/exe")
	if err != nil {
		return fmt.Errorf("checkRunningFsScanner: %w", err)
	}

	for _, file := range matches {
		target, _ := os.Readlink(file)
		if len(target) > 0 && strings.Contains(target, "tetragon-fs-scanner") {
			logger.GetLogger().Warn("Found a running instance of tetragon-fs-scanner on clean start. Killing it.")
			exec.Command("killall", "-9", "tetragon-fs-scanner").Run()
			break
		}
	}

	// There is a case where fs-scanner is killed and the FIFO is not removed. Remove that here just to be sure.
	os.Remove(scannerFifo)

	return nil
}

func startFsScanner() (*exec.Cmd, error) {
	if fm.ScannerFifoPath == "" {
		if option.Config.EnableK8s {
			fm.ScannerFifoPath = path.Join(eeOption.Config.FimFifoPath, fm.ScannerFifoName)
		} else {
			fm.ScannerFifoPath = path.Join(fm.LocalScannerFifoPath, fm.ScannerFifoName)
		}
	}

	execName := path.Join(option.Config.HubbleLib, "tetragon-fs-scanner")
	execFd, err := os.Open(execName)
	if err != nil {
		return nil, fmt.Errorf("startFsScanner: failed to open %s: %w", execName, err)
	}
	defer execFd.Close()

	mntNsId, err := namespace.GetPidNsInode(1, "mnt")
	if err != nil {
		return nil, fmt.Errorf("startFsScanner: failed to get host mnt namespace: %w", err)
	}
	args := []string{fmt.Sprintf("%s/1/ns/mnt", option.Config.ProcFS), execName, "-hostMntNs", strconv.FormatUint(uint64(mntNsId), 10), "-scannerFifoPath", fm.ScannerFifoPath}

	if option.Config.Debug {
		args = append(args, "-debug")
	}

	if eeOption.Config.FimRuntimeEndpoint != "" {
		args = append(args, "-runtimeEndpoint", eeOption.Config.FimRuntimeEndpoint)
	}

	level, levelOk := option.Config.LogOpts["level"]
	if levelOk {
		args = append(args, "-logLevel", level)
	}

	format, formatOk := option.Config.LogOpts["format"]
	if formatOk {
		args = append(args, "-logFormat", format)
	}

	// After an agent crash, tetragon-fs-scanner may be still running.
	// This is the point of a clean start, so we expect no fs-scanner running
	// or the FIFO to exist. We do this check and cleanup appropriately if needed.
	if err := checkRunningFsScanner(fm.ScannerFifoPath); err != nil {
		logger.GetLogger().WithError(err).Warn("checkRunningFsScanner fails")
	}

	ctx, cancel := context.WithCancel(context.Background())
	fsScannerCmd := exec.CommandContext(ctx, path.Join(option.Config.HubbleLib, "tetragon-runner"), args...)
	fsScannerCancelFnMtx.Lock()
	fsScannerCancelFn = cancel
	fsScannerCancelFnMtx.Unlock()

	logger.GetLogger().WithField("args", fsScannerCmd.Args).Info("Agent starting")

	fsScannerCmd.Env = append(fsScannerCmd.Env, fmt.Sprintf("TETRAGON_PROCFS=%s", option.Config.ProcFS))
	fsScannerCmd.Stdout = os.Stdout
	fsScannerCmd.Stderr = os.Stderr
	fsScannerCmd.ExtraFiles = []*os.File{execFd}

	if err := fsScannerCmd.Start(); err != nil {
		return nil, fmt.Errorf("fsScannerCmd.Start(): %w", err)
	}

	// wait for fifo to appear
	retry := 0
	for {
		if _, err := os.Stat(fm.ScannerFifoPath); err == nil {
			break
		}
		if retry > 10 {
			return nil, fmt.Errorf("failed to start tetragon-fs-scanner")
		}
		logger.GetLogger().Infof("tetragon-fs-scanner fifo does not exist [retry = %d]", retry)
		time.Sleep(2 * time.Second)
		retry++
	}

	// We should wait here for the process to stop. Otherwise the FsScanner becomes a zombie.
	go func() {
		if err := fsScannerCmd.Wait(); err != nil {
			logger.GetLogger().WithError(err).Warnf("fsScannerCmd.Wait(): failed with '%s'", err)
		}
	}()

	return fsScannerCmd, nil
}

func killFsScanner() error {
	fsScannerCancelFnMtx.Lock()
	if fsScannerCancelFn != nil {
		fsScannerCancelFn()
		fsScannerCancelFn = nil
	}
	fsScannerCancelFnMtx.Unlock()

	// remove the fifo (if any)
	os.Remove(fm.ScannerFifoPath)

	return nil
}

type observerFileSensor struct {
	name string
}

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterPolicyHandlerAtInit(file.name, file)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE, handleFileOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_RENAME, handleFileRenameOps)
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: rthooksCreateContainer,
	})
	podhooks.RegisterCallbacksAtInit(podhooks.Callbacks{
		PodCallbacks: func(podInformer cache.SharedIndexInformer) {
			podInformer.AddEventHandler(
				cache.ResourceEventHandlerFuncs{
					AddFunc:    podhooksAddFunc,
					UpdateFunc: podhooksUpdateFunc,
					DeleteFunc: podhooksDeleteFunc,
				},
			)
		},
	})
}

func createFsInfoUnix(fs fileapi.MsgFsInfo) file.MsgFsInfoUnix {
	uuid_str := "<failed to parse uuid>"
	u, err := uuid.FromBytes(fs.SUuid[:])
	if err == nil {
		if u == uuid.Nil {
			uuid_str = "" // avoid printing UUID full of 0s
		} else {
			uuid_str = u.String()
		}
	}
	sidIndex := bytes.IndexByte(fs.SId[:], 0)
	snameIndex := bytes.IndexByte(fs.SName[:], 0)

	sid := "error"
	if sidIndex > -1 {
		sid = string(fs.SId[:sidIndex])
	}

	sname := "error"
	if snameIndex > -1 {
		sname = string(fs.SName[:snameIndex])
	}

	return file.MsgFsInfoUnix{
		SName: sname,
		SId:   sid,
		SUuid: uuid_str,
	}
}

func isFileExecEvent(action, hook uint32) bool {
	return action == 0xFFFFFFFF && hook == 0xFFFFFFFF
}

func handleFileOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileOp)
		return nil, fmt.Errorf("Failed to read file operation: %w", err)
	}

	str := strutils.UTF8FromBPFBytes(m.Path.Str[:])
	if uint32(len(str)) > m.Path.Size {
		str = str[:m.Path.Size]
	}

	cid := ""
	if m.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		cid = string(m.Path.ContainerID[:])
	}

	digest := file.MsgDigest{}
	if m.Digest.Ok == 1 {
		if digest.Error = m.Digest.Algo; digest.Error >= 0 { // we don't have an error here
			digestLen := fm.IMA_MAX_DIGEST_SIZE
			if dlen, ok := fm.HashAlgoLen[tetragon.DigestAlgo(m.Digest.Algo)]; ok {
				digestLen = dlen
			}
			for i := 0; i < digestLen; i++ {
				digest.Hash += fmt.Sprintf("%02x", m.Digest.Digest[i])
			}
			digest.Error = 0
		} else {
			// failed to get file digest
			if isFileExecEvent(m.Action, m.Hook) {
				filemetrics.FileFailedDigestInc(filemetrics.FileEventProcessExec)
			} else {
				filemetrics.FileFailedDigestInc(filemetrics.FileEventProcess)
			}
		}
	}

	unix := &file.MsgFileEventUnix{
		Msg:         &m,
		Path:        str,
		Fs:          createFsInfoUnix(m.Fs),
		ParentFs:    createFsInfoUnix(m.ParentFs),
		ContainerID: cid,
		TpName:      pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:      pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		Digest:      digest,
		OpenFlags:   m.OpenFlags,
	}

	return []observer.Event{unix}, nil
}

func hasFlag(flags, flag uint32) bool {
	return (flags & flag) != 0
}

func handleFileRenameOps(r *bytes.Reader) ([]observer.Event, error) {
	l := logger.GetLogger()
	m := fileapi.MsgFileRenameEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMv)
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}

	srcDir := strutils.UTF8FromBPFBytes(m.Src.Path.Dir[:])
	if m.Src.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "/<UNRESOLVED>"
	} else if uint32(len(srcDir)) > m.Src.Path.DirSize {
		srcDir = srcDir[:m.Src.Path.DirSize]
	}

	srcName := strutils.UTF8FromBPFBytes(m.Src.Path.Name[:])
	if uint32(len(srcName)) > m.Src.Path.NameSize {
		srcName = srcName[:m.Src.Path.NameSize]
	}

	srcCid := ""
	if m.Src.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		srcCid = string(m.Src.Path.ContainerID[:])
	}

	dstDir := strutils.UTF8FromBPFBytes(m.Dst.Path.Dir[:])
	if m.Dst.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "/<UNRESOLVED>"
	} else if uint32(len(dstDir)) > m.Dst.Path.DirSize {
		dstDir = dstDir[:m.Dst.Path.DirSize]
	}

	dstName := strutils.UTF8FromBPFBytes(m.Dst.Path.Name[:])
	if uint32(len(dstName)) > m.Dst.Path.NameSize {
		dstName = dstName[:m.Dst.Path.NameSize]
	}

	dstCid := ""
	if m.Dst.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		dstCid = string(m.Dst.Path.ContainerID[:])
	}

	if hasFlag(m.Flags, fm.SRC_DIRECTORY) {
		s, err := pol.FileMonitoringTable.GetFIM(m.TpId)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMvTcId)
			return nil, fmt.Errorf("failed to get fim table index: %w", err)
		}

		renameCid := ""
		if srcCid == "" && dstCid != "" { // use the non-empty
			renameCid = dstCid
		} else if srcCid != "" && dstCid == "" { // use the non-empty
			renameCid = srcCid
		} else if srcCid != "" && dstCid != "" { // both are non-empty
			renameCid = dstCid // both not empty -- use destination containerID
		}

		path := filepath.Join(dstDir, dstName)
		if err := RenameFsScanner(path, option.Config.BpfDir, s.PinPathPrefix, renameCid, s.TpName, *s.Spec, m.Flags); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMvScanner)
			l.WithError(err).Warnf("RenameFsScanner failed!")
		}
	}

	// The following should not be possible to happen. If we catch any of these we should handle them
	// (not difficult to implement)
	if hasFlag(m.Flags, fm.SRC_DIRECTORY) {
		if hasFlag(m.Flags, fm.DST_REG_FILE) {
			if hasFlag(m.Flags, fm.MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, fm.MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_OUTSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, fm.MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INTERNALLY - DST_REG_FILE]")
			}
		}
	} else if hasFlag(m.Flags, fm.SRC_REG_FILE) {
		if hasFlag(m.Flags, fm.DST_DIRECTORY) {
			if hasFlag(m.Flags, fm.MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, fm.MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, fm.MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY]")
			}
		}
	}

	unix := &file.MsgFileRenameEventUnix{
		Msg: &m,
		Src: file.MsgRenameElemUnix{
			Path:        filepath.Join(srcDir, srcName),
			Fs:          createFsInfoUnix(m.Src.Fs),
			ParentFs:    createFsInfoUnix(m.Src.ParentFs),
			ContainerID: srcCid,
		},
		Dst: file.MsgRenameElemUnix{
			Path:        filepath.Join(dstDir, dstName),
			Fs:          createFsInfoUnix(m.Dst.Fs),
			ParentFs:    createFsInfoUnix(m.Dst.ParentFs),
			ContainerID: dstCid,
		},
		TpName: pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule: pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
	}

	return []observer.Event{unix}, nil
}

func addFilter(handle *ebpf.Map, filter string, val fileapi.LPMMapValue) error {
	var k fileapi.LPMMapKey

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	var exKey fileapi.LPMMapKey
	var exVal fileapi.LPMMapValue
	entries := handle.Iterate()
	for entries.Next(&exKey, &exVal) {
		if k.Prefixlen == exKey.Prefixlen && k.Data == exKey.Data { // key already exists
			if exVal.Action == fm.FilterMatch {
				return nil
			}
		}
	}

	err := handle.Update(k, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func addFilters(handle *ebpf.Map, str string, val fileapi.LPMMapValue) error {
	for { // iterate all path components
		if err := addFilter(handle, str, val); err != nil {
			return err
		}

		val = fileapi.LPMMapValue{Action: fm.FilterMonitor} // after the first iteration everything is in monitor state

		if str == "/" { // reached root fs - nothing more to do
			return nil
		}

		// remove the rightmost path component
		str, _ = filepath.Split(strings.TrimSuffix(str, "/"))
	}
}

type FimLoaderData struct {
	s  *fm.KernelSelectorState
	tp string // type of program (i.e. kprobe, kretprobe, lsm, fmod_ret, etc.)
}

func addFileMonitoringSensor(policy tracingpolicy.TracingPolicy, kprobes v1alpha1.FileSpec, fimProgs []FimProg, config fileapi.FileConfigMapValue, sel *fm.KernelSelectorState, tpConf *configFileSensorOptions) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	config.TpId = atomic.AddUint32(&pol.SensorCounter, 1)
	name := fmt.Sprintf("fim_sensor_%d", config.TpId)
	e := &pol.FileMonitoring{
		Spec:          &kprobes,
		PinPathPrefix: name,
		TpName:        policy.TpName(),
		TpRules:       make(map[int]string),
		Config:        &config,
	}
	// Add rules from file_paths with a unique number assosciated to each of them.
	// No need to add file_paths_exclude as we will never get an event from these.
	for i, p := range kprobes.PathsPatterns {
		e.TpRules[i] = fm.PathPatternToString(p)
	}
	pol.FileMonitoringTable.AddFIM(config.TpId, e)

	l := logger.GetLogger()

	exactFilePathMatch := make(map[string]uint32)
	config.NumPatterns = uint32(len(kprobes.PathsPatterns))
	for i, p := range kprobes.PathsPatterns {
		if p.Type == "FileExactMatch" {
			if strings.HasSuffix(p.FileExactMatch.Path, "/") {
				return nil, fmt.Errorf("file path for exact match cannot end with /: [%s]", p.FileExactMatch.Path)
			}
			exactFilePathMatch[p.FileExactMatch.Path] = uint32(i)
		}
	}

	allInodes := make(map[fileapi.InodeKey]fileapi.InodeVal)

	if kprobes.MonitorHostFiles {
		hostInodes, err := TracingPolicyInitFsScanner(policy.TpName(), kprobes, option.Config.BpfDir, e.PinPathPrefix, false)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitScanner)
			l.WithError(err).Warnf("TracingPolicyInitFsScanner failed!")
		} else {
			mapHelpers.Copy(allInodes, hostInodes)
		}
	}
	numHostInodes := len(allInodes)

	// check for existing pod files when we create a new tracing policy
	allContainers := []ContInit{}
	allPodsMu.Lock()
	for _, p := range allPods {
		for _, r := range p.containers {
			allContainers = append(allContainers, ContInit{
				cid:       r.ContainerID,
				namespace: p.podNamespace,
				name:      p.podName,
				root:      r.RootDir,
			})
		}
	}
	allPodsMu.Unlock()
	for _, i := range allContainers {
		s := fm.SpecPinPath{
			PolicyName: policy.TpName(),
			PinPath:    e.PinPathPrefix,
			Spec:       kprobes,
		}
		containerInodes, err := TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{s}, i.cid, i.namespace, i.name, i.root, false)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitContainerScanner)
			logger.GetLogger().WithError(err).Warnf("TracingPolicyInitContainerFsScanner failed")
		} else {
			mapHelpers.Copy(allInodes, containerInodes)
		}
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"total-inodes":   len(allInodes),
		"host-inodes":    numHostInodes,
		"num-pods":       len(allPods),
		"num-containers": len(allContainers),
	}).Infof("Completed path scanning for %s.", e.TpName)

	if tpConf.watchedInodeMapSizePolicy == "auto" {
		config.MaxWatchedInodes = uint32(float32(len(allInodes)) * tpConf.watchedInodeMapSizeMultiplier)
		logger.GetLogger().WithFields(logrus.Fields{
			"max-inode-map-size":      config.MaxWatchedInodes,
			"user-defined-multiplier": tpConf.watchedInodeMapSizeMultiplier,
			"user-defined-constant":   tpConf.watchedInodeMapSizeConstant,
		}).Infof("Using automatic map sizing for %s.", e.TpName)
	} else if tpConf.watchedInodeMapSizePolicy == "fixed" {
		// first check if the fixed size is enough to start the sensor
		if uint32(len(allInodes)) >= tpConf.watchedInodeMapMaxiumSize {
			return nil, fmt.Errorf("the fixed size of inode map (%d) for files is not enough to start the sensor: %d", tpConf.watchedInodeMapMaxiumSize, len(allInodes))
		}
		config.MaxWatchedInodes = tpConf.watchedInodeMapMaxiumSize
		logger.GetLogger().WithFields(logrus.Fields{
			"max-inode-map-size": config.MaxWatchedInodes,
			"user-defined-size":  tpConf.watchedInodeMapMaxiumSize,
		}).Infof("Using fixed map sizing for %s.", e.TpName)
	} else {
		return nil, fmt.Errorf("unknown watchedInodeMapSizePolicy: %s", tpConf.watchedInodeMapSizePolicy)
	}

	// set metric to maximum size of inode map for files
	filemetrics.FileSetInodeMapMax(e.TpName, float64(config.MaxWatchedInodes))

	// make sure that when we do not use the exact match
	// we sert the size of exact_match_map_alloc to 1, otherwise
	// it will fail to load the program.
	exactFilePathMatchSize := uint32(len(exactFilePathMatch))
	if exactFilePathMatchSize == 0 {
		exactFilePathMatchSize = 1
	}

	config.NumSelectors = sel.GetNumSelectors() // pass the total number of selectors
	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			sensors.PathJoin(e.PinPathPrefix, fmt.Sprintf("%s_%s", strings.Replace(h.tp, ".", "_", -1), h.name)),
			"file_monitoring")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		load.SetLoaderData(FimLoaderData{
			s:  sel,
			tp: h.tp,
		})
		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "lpm_trie_map_alloc",
				Load: func(m *ebpf.Map, _ uint32) error {
					for _, str := range kprobes.PathsExclude {
						if err := addFilters(m, str, fileapi.LPMMapValue{Action: fm.FilterIgnore}); err != nil {
							return fmt.Errorf("failed to add ExcludePath: %w", err)
						}
					}
					for i, p := range kprobes.PathsPatterns {
						if p.Type == "FilePrefixSuffix" {
							if err := addFilters(m, p.FilePrefixSuffix.Prefix, fileapi.LPMMapValue{Action: fm.FilterMonitor, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add PathPattern in lpm_trie_map_alloc: %w", err)
							}
						} else if p.Type == "PathPrefix" {
							if err := addFilters(m, p.PathPrefix.Prefix, fileapi.LPMMapValue{Action: fm.FilterMatch, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add WatchPath: %w", err)
							}
						} else if p.Type == "FileExactMatch" {
							if err := addFilters(m, filepath.Dir(p.FileExactMatch.Path), fileapi.LPMMapValue{Action: fm.FilterMonitor, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add PathPattern in lpm_trie_map_alloc: %w", err)
							}
						} else {
							return fmt.Errorf("unknown pattern type: [%s]", p.Type)
						}
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "patterns_map_alloc",
				Load: func(m *ebpf.Map, _ uint32) error {
					for i, p := range kprobes.PathsPatterns {
						if p.Type == "FilePrefixSuffix" {
							key := uint32(i)
							val := fileapi.PatternValue{
								PrefixLen: uint32(len(p.FilePrefixSuffix.Prefix)),
								SuffixLen: uint32(len(p.FilePrefixSuffix.Suffix)),
								Action:    fm.FilterMatch,
								Rule:      uint32(i),
							}

							if val.PrefixLen > 256 || val.SuffixLen > 128 {
								return fmt.Errorf("max prefix size is 256 characters and max suffix size is 128 characters: prefix:[%s], suffix:[%s]", p.FilePrefixSuffix.Prefix, p.FilePrefixSuffix.Suffix)
							}

							copy(val.Prefix[:], []byte(p.FilePrefixSuffix.Prefix))
							copy(val.Suffix[:], []byte(p.FilePrefixSuffix.Suffix))

							if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
								return fmt.Errorf("failed to add PathPattern in patterns_map_alloc: %w", err)
							}
						}
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "hash_map_inode_alloc",
				Load: func(m *ebpf.Map, _ uint32) error {
					for k, v := range allInodes {
						if err := m.Update(k, v, 0); err != nil {
							return err
						}
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "exact_match_map_alloc",
				Load: func(m *ebpf.Map, _ uint32) error {
					for k, v := range exactFilePathMatch {
						key := fileapi.FullPath{}
						copy(key.Path[:], []byte(k))
						if err := m.Update(key, v, 0); err != nil {
							return err
						}
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "tg_mb_sel_opts",
				Load: func(outerMap *ebpf.Map, _ uint32) error {
					return fm.PopulateMatchBinariesMaps(sel, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "tg_mb_paths",
				Load: func(outerMap *ebpf.Map, _ uint32) error {
					return fm.PopulateMatchBinariesPathsMaps(sel, e.PinPathPrefix, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "file_ops_maps",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileOpsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_digests_maps",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileDigestsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_namespaces_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileNamespacesMap(m, sel); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_capabilities_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileCapabilitiesMap(m, sel); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_rename_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileRenameMap(m, sel); err != nil {
						return fmt.Errorf("file_rename_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_open_flags_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileOpenFlagsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("file_open_flags_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_actions_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileActionsMap(m, sel); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_config_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					return m.Update(uint32(0), config, ebpf.UpdateAny)
				},
			},
		}

		// only for exec events when digests are enabled
		if h.name == "security_bprm_check" && h.progName == "bpf_security_bprm_check_enforce_lsm_digest.o" {
			m := "exec_retprobe_map"
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
		}

		// only for io_uring hooks
		if h.name == "io_read" || h.name == "io_write" || h.name == "io_issue_sqe" || h.name == "security_file_permission" {
			m := "io_uring_map"
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
		}

		// only for io_uring hooks
		if h.name == "io_read" || h.name == "io_write" || h.name == "io_issue_sqe" {
			m := "io_uring_retprobe_map"
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
		}

		// only for fsnotify (kernels < 4.18, i.e. rhel8)
		if h.name == "fsnotify" || h.name == "finish_open" || h.name == "vfs_open" {
			m := "fsnotify_created_files_map"
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
		}

		// only for hooks that add files into maps
		if h.name == "finish_open" || h.name == "vfs_open" || h.name == "security_inode_create" || h.name == "vfs_rename" {
			for _, m := range []string{"patterns_map_alloc", "exact_match_map_alloc"} {
				maps = append(
					maps,
					program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
				)
			}
		}

		// only for rename hooks
		if h.name == "vfs_rename" {
			m := "file_rename_map"
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
		}

		for _, m := range SharedMaps {
			m := program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load)
			// custom max entries setup
			switch {
			case m.Name == "tg_mb_paths":
				m.SetInnerMaxEntries(sel.MatchBinariesPathsMaxEntries())
			case m.Name == "file_ops_maps":
				m.SetInnerMaxEntries(int(fm.GetMaxInnerEntriesOpsMap(sel)))
			case m.Name == "file_digests_maps":
				m.SetInnerMaxEntries(int(fm.GetMaxInnerEntriesDigestsMap(sel)))
			case m.Name == "hash_map_inode_alloc":
				m.SetMaxEntries(int(config.MaxWatchedInodes))
			case m.Name == "exact_match_map_alloc":
				m.SetMaxEntries(int(exactFilePathMatchSize))
			}
			maps = append(maps, m)
		}
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
		PreUnloadHook: func() error {
			pol.FileMonitoringTable.RmFIM(config.TpId)
			return nil
		},
	}, nil
}

func fixProgName(p string) string {
	if bpf.HasProgramLargeSize() {
		return p
	}

	needsReplace := map[string]string{
		"bpf_vfs_rename.o":               "bpf_vfs_rename_v419.o",
		"bpf_filemap_fault.o":            "bpf_filemap_fault_v419.o",
		"bpf_filemap_map_pages.o":        "bpf_filemap_map_pages_v419.o",
		"bpf_filemap_page_mkwrite.o":     "bpf_filemap_page_mkwrite_v419.o",
		"bpf_security_file_permission.o": "bpf_security_file_permission_v419.o",
		"bpf_vfs_unlink.o":               "bpf_vfs_unlink_v419.o",
		"bpf_security_inode_setattr.o":   "bpf_security_inode_setattr_v419.o",
		"bpf_vfs_fallocate.o":            "bpf_vfs_fallocate_v419.o",
		"bpf_finish_open.o":              "bpf_finish_open_v419.o",
		"bpf_vfs_open.o":                 "bpf_vfs_open_v419.o",
		"bpf_security_inode_rmdir.o":     "bpf_security_inode_rmdir_v419.o",
		"bpf_vfs_mkdir.o":                "bpf_vfs_mkdir_v419.o",
		"bpf_iterate_dir.o":              "bpf_iterate_dir_v419.o",
		"bpf_security_bprm_check.o":      "bpf_security_bprm_check_v419.o",
		"bpf_security_path_rename.o":     "bpf_security_path_rename_v419.o",
		"bpf_security_inode_link.o":      "bpf_security_inode_link_v419.o",
		"bpf_security_file_open.o":       "bpf_security_file_open_v419.o",
	}

	r, ok := needsReplace[p]
	if ok {
		return r
	}
	return p
}

func getIoUringHooks(spec *btf.Spec, ioUringSupport bool, hooks []FimHook) []FimHook {
	if !ioUringSupport {
		return hooks
	}

	hasIoRead := false
	if _, err := fgsBTF.GetFuncProto(spec, "io_read", false); err == nil {
		hasIoRead = true
	}

	hasIoWrite := false
	if _, err := fgsBTF.GetFuncProto(spec, "io_write", false); err == nil {
		hasIoWrite = true
	}

	hasIoReadWrite := hasIoRead && hasIoWrite

	// first we try to load io_read and io_write hooks
	if hasIoReadWrite {
		return append(hooks, FimIoUringHooks[:]...)
	}

	logger.GetLogger().WithFields(logrus.Fields{"io_read": hasIoRead, "io_write": hasIoWrite}).Warn("Cannot find io_read/io_write hooks for io_uring. Falling back to io_issue_sqe.")

	// if they are unavailable we try to load io_issue_sqe hook
	return append(hooks, FimIoUringSingleHooks[:]...)
}

func getFileCreateHooks(spec *btf.Spec, hooks []FimHook, config *fileapi.FileConfigMapValue) []FimHook {
	vfsOpenProto, err1 := fgsBTF.GetFuncProto(spec, "vfs_open", false)
	finishOpenProto, err2 := fgsBTF.GetFuncProto(spec, "finish_open", false)
	if err1 == nil && err2 == nil && vfsOpenProto == FimHooksFileCreate[1].prog[0].proto && finishOpenProto == FimHooksFileCreate[0].prog[0].proto {
		return append(hooks, FimHooksFileCreate[:]...)
	}

	// In newer kernels (>= 4.19), we rely on (file->f_mode & FMODE_CREATED)
	// to check if a file is created.
	// Older kernels (< 4.19, i.e. 4.18 rhel8) use a different way to provide
	// the information if the file is created. This is done by using an argument
	// (int *opened) in finish_open hook. More specifically, we could use something
	// like (*opened & FILE_CREATED) to determine if a file is created. The problem
	// is that vfs_open hook does not have this argument to cover all cases.
	// Using hooks in lower functions (i.e. lookup_open) is not possible as they
	// are static and they are inlined in rhel8.
	// To support those kernels, we also hook at the fsnotify hook. We do some
	// checks to get events only for newly created file and we add the inode pair
	// (i.e. file and directory inodes) into a map (fsnotify_created_files_map).
	// Then we consume these from the normal hooks that we use for file creates.
	config.IsLessThan419 = 1
	return append(hooks, FimHooksFileCreate418[:]...)
}

func findHooks(config *fileapi.FileConfigMapValue, mode Mode, digestSupport, ioUringSupport bool) ([]FimProg, error) {
	spec, err := ossBTF.NewBTF()
	if err != nil {
		return nil, fmt.Errorf("GetCachedBTF error: %s", err)
	}
	if spec == nil {
		return nil, fmt.Errorf("GetCachedBTF returns nil")
	}

	var fnType *btf.Struct
	hasOverlaySymbols = (spec.TypeByName("ovl_entry", &fnType) == nil)
	if _, err := os.Stat(filepath.Join(btfPath, overlayModName)); err == nil {
		hasOverlayBTF = true
	}

	if !hasOverlaySymbols && hasOverlayBTF {
		// Overlay is a module and here we load its symbols.
		if newSpec, err := ossBTF.AddModulesToSpec(spec, []string{overlayModName}); err == nil {
			spec = newSpec
		}
	}

	var hooks []FimHook
	m := ""
	if mode == Observe {
		hooks = FimHooksObserve[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "observe"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksObserveExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	} else if mode == EnforceFmodRet {
		hooks = FimHooksFmodRet[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "enforce with fmod_ret"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksFmodRetExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	} else if mode == EnforceLSM {
		hooks = FimHooksLsm[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "enforce with lsm"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksLsmExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	} else {
		return nil, fmt.Errorf("unknown mode in findHooks [%d]", mode)
	}
	logger.GetLogger().Infof("Loading file hooks for %s", m)

	fimProgs := make([]FimProg, 0)
	for _, h := range hooks {
		// In GKE 5.15 kernels io_read and io_write functions seems to be inlined.
		// On the other hand, io_issue_sqe seems to be available. We can find
		// that in /proc/kallsyms but not in the BTF. For this reason, we skip the
		// BTF check here and we try to load hooks in io_issue_sqe. If this fails
		// to attach that hook, fim will fail to load. The prototype of io_issue_sqe
		// seems to be stable along all kernels that have this function.
		if h.name == "io_issue_sqe" {
			fimProgs = append(fimProgs, FimProg{h.tp, h.name, h.prog[0].progName, h.prog[0].progSection})
			continue
		}

		kretprobe := (h.tp == "kretprobe")
		p, err := fgsBTF.GetFuncProto(spec, h.name, kretprobe)
		if err != nil {
			if h.name == "security_path_rename" {
				logger.GetLogger().Warnf("failed to find %s/security_path_rename hook, will continue without it", h.tp)
				config.HasSecurityPathRename = 0
				continue
			}
			return nil, fmt.Errorf("fgsBTF.GetFuncProto failed: %w", err)
		}

		progFound := false
		for _, f := range h.prog {
			if f.proto == p {
				progFound = true
				fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(f.progName), f.progSection})
				break
			}
		}
		if !progFound {
			return nil, fmt.Errorf("function %s has different prototype in BTF (BTF: %s) compared to FIM", h.name, p)
		}
	}

	return fimProgs, nil
}

// returns the mode (i.e. Observe, Enforce etc.) and if the kernel supports file digests
func probeFileMode(s *fm.KernelSelectorState) (Mode, bool) {
	supportTracing := (probeTracingModifyReturn() == nil)
	logger.GetLogger().Infof("probeTracingModifyReturn() = %t", supportTracing)
	logger.GetLogger().Infof("HaveProgramType(ebpf.Tracing) = %t", (features.HaveProgramType(ebpf.Tracing) == nil))

	supportLSM := (probeLSM() == nil)
	supportImaFileHash := (probeImaFileHashHelper() == nil)
	logger.GetLogger().Infof("probeLSM() = %t probeImaFileHashHelper() = %t", supportLSM, supportImaFileHash)
	logger.GetLogger().Infof("HaveProgramType(ebpf.LSM) = %t", (features.HaveProgramType(ebpf.LSM) == nil))

	digestSupport := supportLSM && supportImaFileHash

	if !s.NeedEnforcement() {
		return Observe, digestSupport
	}

	// If we have support for lsm and fmod_ret we prefer to use lsm.
	if supportLSM {
		return EnforceLSM, digestSupport
	} else if supportTracing {
		return EnforceFmodRet, digestSupport
	}
	return EnforceNotSupported, digestSupport
}

type configFileSensorOptions struct {
	forceLoad                     bool
	enableExecDigests             bool
	watchedInodeMapSizePolicy     string
	watchedInodeMapMaxiumSize     uint32
	watchedInodeMapSizeMultiplier float32
	watchedInodeMapSizeConstant   uint32
}

func configFileSensorOptionsInit(opts map[string]string) (*configFileSensorOptions, error) {
	conf := configFileSensorOptions{
		forceLoad:                     false,
		enableExecDigests:             false,
		watchedInodeMapSizePolicy:     "fixed",
		watchedInodeMapMaxiumSize:     256 * 1024, // 256K
		watchedInodeMapSizeMultiplier: 4.0,
		watchedInodeMapSizeConstant:   256 * 1024, // 256K
	}

	if val, ok := opts["forceLoad"]; ok {
		boolValue, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.forceLoad should be a boolean. User input: [%s]", val)
		}
		conf.forceLoad = boolValue
	}

	if val, ok := opts["enableExecDigests"]; ok {
		boolValue, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.enableExecDigests should be a boolean. User input: [%s]", val)
		}
		conf.enableExecDigests = boolValue
	}

	if val, ok := opts["watchedInodeMapMaxiumSize"]; ok {
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapMaxiumSize should be a number. User input: [%s]", val)
		}
		conf.watchedInodeMapMaxiumSize = uint32(v)
	}

	if val, ok := opts["watchedInodeMapSizePolicy"]; ok {
		if val != "fixed" && val != "auto" {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizePolicy should be fixed or dynamic. User input: [%s]", val)
		}
		conf.watchedInodeMapSizePolicy = val
	}

	if val, ok := opts["watchedInodeMapSizeMultiplier"]; ok {
		v, err := strconv.ParseFloat(val, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizeMultiplier should be a float. User input: [%s]", val)
		}
		conf.watchedInodeMapSizeMultiplier = float32(v)
	}

	if val, ok := opts["watchedInodeMapSizeConstant"]; ok {
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizeConstant should be a number. User input: [%s]", val)
		}
		conf.watchedInodeMapSizeConstant = uint32(v)
	}

	return &conf, nil
}

func (k *observerFileSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()

	newFileSpec := spec.FileMonitoring.DeepCopy()
	for _, p := range spec.FileMonitoring.Paths {
		newFileSpec.PathsPatterns = append(newFileSpec.PathsPatterns, v1alpha1.FilePathPattern{
			Type: "PathPrefix",
			PathPrefix: &v1alpha1.PathPrefixPattern{
				Prefix: p,
			},
		})
	}
	newFileSpec.Paths = nil

	if len(spec.FileMonitoring.Paths) == 0 && len(spec.FileMonitoring.PathsPatterns) == 0 {
		return nil, nil
	}

	if len(spec.FileMonitoring.Paths) > 0 && len(spec.FileMonitoring.PathsPatterns) > 0 {
		return nil, fmt.Errorf("FileMonitoring requires only one of file_paths or file_paths_patterns to be defined")
	}

	tpConf, err := configFileSensorOptionsInit(spec.FileMonitoring.Config)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse config: %w", err)
	}

	if !tpConf.forceLoad && !kernels.MinKernelVersion("4.18.0") {
		return nil, fmt.Errorf("FileMonitoring requires at least 4.18.0 version")
	}
	logger.GetLogger().Infof("FileMonitoring is enabled with %d prefixes and %d patterns to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsPatterns), len(spec.FileMonitoring.PathsExclude))

	if !spec.FileMonitoring.MonitorHostFiles && spec.FileMonitoring.PodSelector == nil {
		logger.GetLogger().Warnf("FileMonitoring policy with false monitorHostFile and nil PodSelector will not match anything")
	}

	selState, err := fm.InitKernelSelectorState(spec.FileMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse selectors: %w", err)
	}

	// start tetragon-fs-scanner if it hasn't started yet
	if _, serr := os.Stat(fm.ScannerFifoPath); fsScannerCmd == nil || errors.Is(serr, os.ErrNotExist) {
		var err error
		fsScannerCmd, err = startFsScanner()
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring failed to start tetragon-fs-scanner: %w", err)
		}
	}

	ioUringSupport := fm.SupportIoUring()
	logger.GetLogger().Infof("FileMonitoring kernel supports io_uring: %t", ioUringSupport)

	config := fileapi.FileConfigMapValue{
		HasSecurityPathRename: 1,
		PolicyId:              uint32(fid),
	}
	fileMode, digestSupport := probeFileMode(selState)
	if !tpConf.enableExecDigests { // we explicitly disable digests if the user has not enabled them
		digestSupport = false
	}
	if tpConf.enableExecDigests && !digestSupport { // the user enables exec digests but the kernel does not support them
		logger.GetLogger().Warn("FileMonitoring: User enables file digests but the kernel does not support them. Falling back to not using them.")
	}
	progs, err := findHooks(&config, fileMode, digestSupport, ioUringSupport)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring fails to find the appropriate hooks: %w", err)
	}
	return addFileMonitoringSensor(policy, *newFileSpec, progs, config, selState, tpConf)
}

func loadProbe(args sensors.LoadProbeArgs) error {
	v, ok := args.Load.LoaderData.(FimLoaderData)
	if !ok {
		return fmt.Errorf("type of LoaderData does not match FimLoaderData")
	}

	oldKmods := option.Config.KMods
	if !hasOverlaySymbols && hasOverlayBTF {
		option.Config.KMods = []string{overlayModName} // FIM only needs overlay module symbols
	}

	var err error
	switch v.tp {
	case "kprobe", "kretprobe":
		err = program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
	case "fentry", "fexit", "fmod_ret":
		err = program.LoadTracingProgram(args.BPFDir, args.Load, args.Verbose)
	case "lsm", "lsm.s":
		err = program.LoadLSMProgram(args.BPFDir, args.Load, args.Verbose)
	default:
		err = fmt.Errorf("file: %s programs are not supported", v.tp)
	}

	if !hasOverlaySymbols && hasOverlayBTF {
		option.Config.KMods = oldKmods
	}

	return err
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}
