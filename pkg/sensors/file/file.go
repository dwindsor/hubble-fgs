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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
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
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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
	maxLPMpaths     = 4096
	maxWatchedDirs  = 128 * 1024 // 128K
	maxWatchedFiles = 128 * 1024 // 128K
)

const (
	MOVE_INSIDE     = (1 << 0)
	MOVE_OUTSIDE    = (1 << 1)
	MOVE_INTERNALLY = (1 << 2)
	SRC_REG_FILE    = (1 << 3)
	SRC_DIRECTORY   = (1 << 4)
	SRC_CHAR_DEV    = (1 << 5)
	SRC_BLOCK_DEV   = (1 << 6)
	SRC_NAMED_PIPE  = (1 << 7)
	SRC_SYMLINK     = (1 << 8)
	SRC_SOCKET      = (1 << 9)
	SRC_INVALID     = (1 << 10)
	DST_NOT_EXISTS  = (1 << 11)
	DST_REG_FILE    = (1 << 12)
	DST_DIRECTORY   = (1 << 13)
	DST_CHAR_DEV    = (1 << 14)
	DST_BLOCK_DEV   = (1 << 15)
	DST_NAMED_PIPE  = (1 << 16)
	DST_SYMLINK     = (1 << 17)
	DST_SOCKET      = (1 << 18)
	DST_INVALID     = (1 << 19)
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
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
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
	}

	FimHooksObserveExec = FimHook{"kprobe", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check.o", "security_bprm_check"}}}

	FimHooksFmodRet = [...]FimHook{
		{"fmod_ret", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_fmod.o", "security_mmap_file"}}},
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_fmod.o", "security_file_permission"}}},
		{"fmod_ret", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_fmod.o", "security_inode_unlink"}}},
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
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
	}

	FimHooksFmodRetExec = FimHook{"fmod_ret", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_fmod.o", "security_bprm_check"}}}

	FimHooksLsm = [...]FimHook{
		{"lsm", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_lsm.o", "mmap_file"}}},
		{"lsm", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_lsm.o", "file_permission"}}},
		{"lsm", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_lsm.o", "inode_unlink"}}},
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
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

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"rename_retprobe_map",
		"spr_retprobe_map",
		"vr_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_file_alloc",
		"hash_map_dir_alloc",
		"tg_mb_sel_opts",
		"tg_mb_paths",
		"file_ops_maps",
		"file_namespaces_map",
		"file_capabilities_map",
		"file_digests_maps",
		"file_actions_map",
		"file_config_map",
	}
)

func TerminateFsScanner() error {
	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc("sensor_file_rpc_terminate")
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

func TracingPolicyInitFsScanner(tpName string, s v1alpha1.FileSpec, m string, pin string) error {
	f := fm.FsScannerInit{
		PolicyName: tpName,
		Spec:       s,
		MapDir:     m,
		PinPath:    pin,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc("sensor_file_rpc_init_host")
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.TracingPolicyInit", &f, &struct{}{})
}

func RenameFsScanner(p string, m string, o uint32, a uint32, pin string, cid string, r uint32) error {
	f := fm.FsScannerRename{
		Path:        p,
		MapDir:      m,
		Op:          o,
		Action:      a,
		PinPath:     pin,
		ContainerID: cid,
		RuleID:      r,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc("sensor_file_rpc_scanner")
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.RenameDir", &f, &struct{}{})
}

func TracingPolicyInitContainerFsScanner(specPath []fm.SpecPinPath, containerID, podNs, podName, rootDir string) error {
	if len(specPath) == 0 {
		specPath = pol.FileMonitoringTable.GetValuesFIM()
	}
	f := fm.FsScannerContainerInit{
		Tp:          specPath,
		MapDir:      option.Config.MapDir,
		ContainerID: containerID,
		PodNs:       podNs,
		PodName:     podName,
		RootDir:     rootDir,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc("sensor_file_rpc_init_cont")
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.TracingPolicyContainerInit", &f, &struct{}{})
}

func TracingPolicyDestroyContainerFsScanner(containerID string) error {
	specPath := pol.FileMonitoringTable.GetValuesFIM()
	f := fm.FsScannerContainerDestroy{
		Tp:          specPath,
		MapDir:      option.Config.MapDir,
		ContainerID: containerID,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc("sensor_file_rpc_destroy_cont")
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
		if len(target) > 0 && strings.Contains(target, "hubble-fgs-fs-scanner") {
			logger.GetLogger().Warn("Found a running instance of hubble-fgs-fs-scanner on clean start. Killing it.")
			exec.Command("killall", "-9", "hubble-fgs-fs-scanner").Run()
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

	execName := path.Join(option.Config.HubbleLib, "hubble-fgs-fs-scanner")
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

	// After an agent crash, hubble-fgs-fs-scanner may be still running.
	// This is the point of a clean start, so we expect no fs-scanner running
	// or the FIFO to exist. We do this check and cleanup appropriately if needed.
	if err := checkRunningFsScanner(fm.ScannerFifoPath); err != nil {
		logger.GetLogger().WithError(err).Warn("checkRunningFsScanner fails")
	}

	ctx, cancel := context.WithCancel(context.Background())
	fsScannerCmd := exec.CommandContext(ctx, path.Join(option.Config.HubbleLib, "hubble-fgs-runner"), args...)
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
			return nil, fmt.Errorf("failed to start hubble-fgs-fs-scanner")
		}
		logger.GetLogger().Infof("hubble-fgs-fs-scanner fifo does not exist [retry = %d]", retry)
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

type observerFileExecSensor struct {
	name string
}

// only for testing
// remove all entries of a map
func cleanupMap[K any, V any](pinPathPrefix string, mapName string) error {
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(pinPathPrefix, mapName))
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	var key K
	var val V
	for {
		entries := handle.Iterate()
		keyFound := false
		for entries.Next(&key, &val) {
			handle.Delete(key)
			keyFound = true
			break

		}
		if !keyFound {
			break
		}
	}

	return nil
}

func cleanupArrayMapMbPaths(pinPathPrefix string, mapName string) error {
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(pinPathPrefix, mapName))
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	info, _ := handle.Info()
	for i := uint32(0); i < info.MaxEntries; i++ {
		var val int32
		if err := handle.Lookup(i, &val); err == nil {
			if err = handle.Delete(i); err != nil {
				return fmt.Errorf("cleanupArrayMapMbPaths delete failed: %w", err)
			}
		}
	}
	return nil
}

func cleanupArrayMapSelOpts(pinPathPrefix string, mapName string) error {
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(pinPathPrefix, mapName))
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	info, _ := handle.Info()
	for i := uint32(0); i < info.MaxEntries; i++ {
		val := selectors.MatchBinariesSelectorOptions{
			Op:    0,
			MapID: 0,
		}
		err := handle.Update(i, &val, 0)
		if err != nil {
			return fmt.Errorf("cleanupArrayMapSelOpts update failed: %w", err)
		}
	}
	return nil
}

// only for testing
// remove all entries of all FIM maps
func cleanupFIMMaps(tc *pol.FileMonitoring) error {
	if err := cleanupMap[fileapi.LPMMapKey, fileapi.LPMMapValue](tc.PinPathPrefix, "lpm_trie_map_alloc"); err != nil {
		return err
	}
	if err := cleanupMap[fileapi.HashMapFileKey, fileapi.HashMapFileVal](tc.PinPathPrefix, "hash_map_file_alloc"); err != nil {
		return err
	}
	if err := cleanupMap[fileapi.HashMapFileKey, fileapi.HashMapFileVal](tc.PinPathPrefix, "hash_map_dir_alloc"); err != nil {
		return err
	}
	if err := cleanupArrayMapSelOpts(tc.PinPathPrefix, "tg_mb_sel_opts"); err != nil {
		return err
	}
	if err := cleanupArrayMapMbPaths(tc.PinPathPrefix, "tg_mb_paths"); err != nil {
		return err
	}
	if err := cleanupMap[uint32, uint32](tc.PinPathPrefix, "file_ops_maps"); err != nil {
		return err
	}
	if err := cleanupMap[fileapi.DigestKey, uint32](tc.PinPathPrefix, "file_digests_maps"); err != nil {
		return err
	}
	if err := cleanupMap[uint32, uint32](tc.PinPathPrefix, "file_actions_map"); err != nil {
		return err
	}

	return nil
}

// only for testing
// generate the contents of FIM maps (the maps already exist and are empty)
func generateFIMMaps(tc *pol.FileMonitoring, spec *v1alpha1.FileSpec) error {
	tc.Spec = spec
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "lpm_trie_map_alloc"))
	lpmMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer lpmMap.Close()

	for _, str := range spec.Paths {
		if err := addFilters(lpmMap, str, fileapi.LPMMapValue{Action: fm.FilterMatch}); err != nil {
			return fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range spec.PathsExclude {
		if err := addFilters(lpmMap, str, fileapi.LPMMapValue{Action: fm.FilterIgnore}); err != nil {
			return fmt.Errorf("failed to add ExcludePath: %w", err)
		}
	}

	if spec.MonitorHostFiles {
		if err := TracingPolicyInitFsScanner("test-policy", *spec, mapDir, tc.PinPathPrefix); err != nil {
			return err
		}
	}

	sel, err := fm.InitKernelSelectorState(spec.Selectors)
	if err != nil {
		return fmt.Errorf("failed to initialize kernel selector state: %w", err)
	}

	configMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "file_config_map"))
	configMap, err := ebpf.LoadPinnedMap(configMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", configMapPath)
	}
	defer configMap.Close()

	tc.Config.NumSelectors = sel.GetNumSelectors()
	if err := configMap.Update(uint32(0), *tc.Config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to insert %v: %w", sel, err)
	}

	mbSelOptsPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "tg_mb_sel_opts"))
	mbSelOpts, err := ebpf.LoadPinnedMap(mbSelOptsPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mbSelOptsPath)
	}
	defer mbSelOpts.Close()

	if err := fm.PopulateMatchBinariesMaps(sel, mbSelOpts); err != nil {
		return fmt.Errorf("failed to populate tg_mb_sel_opts: %w", err)
	}

	mbPathsPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "tg_mb_paths"))
	mbPaths, err := ebpf.LoadPinnedMap(mbPathsPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mbPathsPath)
	}
	defer mbPaths.Close()

	if err := fm.PopulateMatchBinariesPathsMaps(sel, tc.PinPathPrefix, mbPaths); err != nil {
		return fmt.Errorf("failed to populate tg_mb_paths: %w", err)
	}

	selOpsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "file_ops_maps"))
	selOpsHandle, err := ebpf.LoadPinnedMap(selOpsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selOpsHandle.Close()

	if err := fm.GenerateFileOpsMap(selOpsHandle, sel, tc.PinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_ops_maps: %w", err)
	}

	selDigestsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "file_digests_maps"))
	selDigestsHandle, err := ebpf.LoadPinnedMap(selDigestsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selDigestsHandle.Close()

	if err := fm.GenerateFileDigestsMap(selDigestsHandle, sel, tc.PinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_digests_maps: %w", err)
	}

	selActionsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.PinPathPrefix, "file_actions_map"))
	selActionsHandle, err := ebpf.LoadPinnedMap(selActionsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selActionsMapPath)
	}
	defer selActionsHandle.Close()

	if err := fm.GenerateFileActionsMap(selActionsHandle, sel); err != nil {
		return fmt.Errorf("failed to populate file_actions_map")
	}

	return nil
}

// only for testing
// cleanup and re-generate the contents of FIM maps
// the maps (and programs) are loaded during the whole time of this procedure
func reGenerateFimMaps(spec *v1alpha1.FileSpec) error {
	tc, put, err := pol.FileMonitoringTable.GetOneLockedOrFail()
	if err != nil {
		return err
	}
	defer put()

	if err := cleanupFIMMaps(tc); err != nil {
		return err
	}

	return generateFIMMaps(tc, spec)
}

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterPolicyHandlerAtInit(file.name, file)

	fileExec := &observerFileExecSensor{
		name: "file exec sensor",
	}
	sensors.RegisterProbeType("file_exec_monitoring", fileExec)
	sensors.RegisterPolicyHandlerAtInit(fileExec.name, fileExec)

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
		SDev:  fs.SDev,
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
		filemetrics.FileTotalErrorsInc("sensor_file_op")
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
		digest.Ok = true
		if digest.Error = m.Digest.Algo; digest.Error >= 0 { // we don't have an error here
			digest.Algo = m.Digest.Algo
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
				filemetrics.FileFailedDigestInc("process_file_exec")
			} else {
				filemetrics.FileFailedDigestInc("process_file")
			}
		}
	}

	unix := &file.MsgFileEventUnix{
		Common:      m.Common,
		ProcessKey:  m.ProcessKey,
		Path:        str,
		Action:      m.Action,
		Hook:        m.Hook,
		Timestamp:   m.Timestamp,
		Imode:       uint32(m.Imode[0]),
		NewImode:    uint32(m.Imode[1]),
		Uid:         m.Uid[0],
		NewUid:      m.Uid[1],
		Gid:         m.Gid[0],
		NewGid:      m.Gid[1],
		Ino:         m.Ino,
		Fs:          createFsInfoUnix(m.Fs),
		ParentIno:   m.ParentIno,
		ParentFs:    createFsInfoUnix(m.ParentFs),
		ContainerID: cid,
		MntNs:       m.MntNs,
		Operation:   m.Operation,
		TpName:      pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:      pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		Tid:         m.Tid,
		Digest:      digest,
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
		filemetrics.FileTotalErrorsInc("sensor_file_mv")
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}

	srcDir := strutils.UTF8FromBPFBytes(m.Src.Path.Dir[:])
	if m.Src.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "<UNRESOLVED>"
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
		srcDir = "<UNRESOLVED>"
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

	if hasFlag(m.Flags, SRC_DIRECTORY) {
		var op uint32
		var action uint32

		path := filepath.Join(dstDir, dstName)
		if hasFlag(m.Flags, MOVE_INSIDE) || hasFlag(m.Flags, MOVE_INTERNALLY) {
			op = fm.AddToMap
			action = fm.FilterMatch
		} else if hasFlag(m.Flags, MOVE_OUTSIDE) {
			op = fm.RemoveFromMap
			action = fm.FilterIgnore
		}

		s, err := pol.FileMonitoringTable.GetFIM(m.TpId)
		if err != nil {
			filemetrics.FileTotalErrorsInc("sensor_file_mv_tcid")
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

		if err := RenameFsScanner(path, option.Config.MapDir, op, action, s.PinPathPrefix, renameCid, m.RuleID); err != nil {
			filemetrics.FileTotalErrorsInc("sensor_file_mv_scanner")
			l.WithError(err).Warnf("RenameFsScanner failed!")
		}
	}

	// The following should not be possible to happen. If we catch any of these we should handle them
	// (not difficult to implement)
	if hasFlag(m.Flags, SRC_DIRECTORY) {
		if hasFlag(m.Flags, DST_REG_FILE) {
			if hasFlag(m.Flags, MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_OUTSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INTERNALLY - DST_REG_FILE]")
			}
		}
	} else if hasFlag(m.Flags, SRC_REG_FILE) {
		if hasFlag(m.Flags, DST_DIRECTORY) {
			if hasFlag(m.Flags, MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY]")
			}
		}
	}

	unix := &file.MsgFileRenameEventUnix{
		Common:     m.Common,
		ProcessKey: m.ProcessKey,
		Action:     m.Action,
		Hook:       m.Hook,
		Timestamp:  m.Timestamp,
		Src: file.MsgRenameElemUnix{
			Path:        filepath.Join(srcDir, srcName),
			Ino:         m.Src.Ino,
			Fs:          createFsInfoUnix(m.Src.Fs),
			ParentIno:   m.Src.ParentIno,
			ParentFs:    createFsInfoUnix(m.Src.ParentFs),
			ContainerID: srcCid,
		},
		Dst: file.MsgRenameElemUnix{
			Path:        filepath.Join(dstDir, dstName),
			Ino:         m.Dst.Ino,
			Fs:          createFsInfoUnix(m.Dst.Fs),
			ParentIno:   m.Dst.ParentIno,
			ParentFs:    createFsInfoUnix(m.Dst.ParentFs),
			ContainerID: dstCid,
		},
		MntNs:     m.MntNs,
		Flags:     m.Flags,
		Operation: m.Operation,
		TpName:    pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:    pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		Tid:       m.Tid,
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

func addFileMonitoringSensor(policy tracingpolicy.TracingPolicy, kprobes v1alpha1.FileSpec, fimProgs []FimProg, config fileapi.FileConfigMapValue, sel *fm.KernelSelectorState) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var err error

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
	for i, p := range kprobes.Paths {
		e.TpRules[i] = p
	}
	pol.FileMonitoringTable.AddFIM(config.TpId, e)

	l := logger.GetLogger()
	mapDir := bpf.MapPrefixPath()
	os.Mkdir(mapDir, os.ModeDir)

	ms := &ebpf.MapSpec{
		Name:       "lpm_trie_map_alloc",
		Type:       bpf.BPF_MAP_TYPE_LPM_TRIE,
		KeySize:    uint32(unsafe.Sizeof(fileapi.LPMMapKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.LPMMapValue{})),
		MaxEntries: maxLPMpaths,
		Flags:      bpf.BPF_F_NO_PREALLOC,
	}

	lpmMap, err := ebpf.NewMapWithOptions(ms, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}
	defer lpmMap.Close()

	lpmPinPath := path.Join(mapDir, sensors.PathJoin(e.PinPathPrefix, "lpm_trie_map_alloc"))
	// remove the map if already exists, otheriwse Pin() will fail
	if _, err := os.Stat(lpmPinPath); err == nil {
		os.Remove(lpmPinPath)
	}
	if err := lpmMap.Pin(lpmPinPath); err != nil {
		return nil, fmt.Errorf("failed lpmMap.Pin: %w", err)
	}

	for _, str := range kprobes.Paths {
		if err := addFilters(lpmMap, str, fileapi.LPMMapValue{Action: fm.FilterMatch}); err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range kprobes.PathsExclude {
		if err := addFilters(lpmMap, str, fileapi.LPMMapValue{Action: fm.FilterIgnore}); err != nil {
			return nil, fmt.Errorf("failed to add ExcludePath: %w", err)
		}
	}

	hs := &ebpf.MapSpec{
		Name:       "hash_map_file_alloc",
		Type:       bpf.BPF_MAP_TYPE_HASH,
		KeySize:    uint32(unsafe.Sizeof(fileapi.HashMapFileKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.HashMapFileVal{})),
		MaxEntries: config.MaxWatchedFiles,
		Flags:      0,
	}

	fileHandle, err := ebpf.NewMapWithOptions(hs, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}
	defer fileHandle.Close()

	filePinPath := path.Join(mapDir, sensors.PathJoin(e.PinPathPrefix, "hash_map_file_alloc"))
	// remove the map if already exists, otheriwse Pin() will fail
	if _, err := os.Stat(filePinPath); err == nil {
		os.Remove(filePinPath)
	}
	if err := fileHandle.Pin(filePinPath); err != nil {
		return nil, fmt.Errorf("failed fileHandle.Pin: %w", err)
	}

	// set metric to maximum size of inode map for files
	filemetrics.FileSetFileInodeMapMax(e.TpName, float64(config.MaxWatchedFiles))

	ds := &ebpf.MapSpec{
		Name:       "hash_map_dir_alloc",
		Type:       bpf.BPF_MAP_TYPE_HASH,
		KeySize:    uint32(unsafe.Sizeof(fileapi.HashMapFileKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.HashMapFileVal{})),
		MaxEntries: config.MaxWatchedDirs,
		Flags:      0,
	}

	dirHandle, err := ebpf.NewMapWithOptions(ds, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}
	defer dirHandle.Close()

	dirPinPath := path.Join(mapDir, sensors.PathJoin(e.PinPathPrefix, "hash_map_dir_alloc"))
	// remove the map if already exists, otheriwse Pin() will fail
	if _, err := os.Stat(dirPinPath); err == nil {
		os.Remove(dirPinPath)
	}
	if err := dirHandle.Pin(dirPinPath); err != nil {
		return nil, fmt.Errorf("failed dirHandle.Pin: %w", err)
	}

	// set metric to maximum size of inode map for directories
	filemetrics.FileSetDirectoryInodeMapMax(e.TpName, float64(config.MaxWatchedDirs))

	if kprobes.MonitorHostFiles {
		if err := TracingPolicyInitFsScanner(policy.TpName(), kprobes, option.Config.MapDir, e.PinPathPrefix); err != nil {
			filemetrics.FileTotalErrorsInc("sensor_file_init_scanner")
			l.WithError(err).Warnf("TracingPolicyInitFsScanner failed!")
		}
	}

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
		if err := TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{s}, i.cid, i.namespace, i.name, i.root); err != nil {
			filemetrics.FileTotalErrorsInc("sensor_file_init_container_scanner")
			logger.GetLogger().WithError(err).Warnf("TracingPolicyInitContainerFsScanner failed")
		}
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
		load.MaxEntriesInnerMap = map[string]uint32{
			"tg_mb_paths":       uint32(sel.MatchBinariesPathsMaxEntries()),
			"file_ops_maps":     fm.GetMaxInnerEntriesOpsMap(sel),
			"file_digests_maps": fm.GetMaxInnerEntriesDigestsMap(sel),
		}
		load.MaxEntriesMap = map[string]uint32{
			"hash_map_file_alloc": config.MaxWatchedFiles,
			"hash_map_dir_alloc":  config.MaxWatchedDirs,
		}
		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "tg_mb_sel_opts",
				Load: func(outerMap *ebpf.Map, index uint32) error {
					return fm.PopulateMatchBinariesMaps(sel, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "tg_mb_paths",
				Load: func(outerMap *ebpf.Map, index uint32) error {
					return fm.PopulateMatchBinariesPathsMaps(sel, e.PinPathPrefix, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "file_ops_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileOpsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_digests_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileDigestsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_namespaces_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileNamespacesMap(m, sel); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_capabilities_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileCapabilitiesMap(m, sel); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_actions_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileActionsMap(m, sel); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_config_map",
				Load: func(m *ebpf.Map, index uint32) error {
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

		for _, m := range SharedMaps {
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.PinPathPrefix, m), load),
			)
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
	if !kernels.IsKernelVersionLessThan("5.3.0") {
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

func findHooks(config *fileapi.FileConfigMapValue, mode Mode, digestSupport, ioUringSupport bool) ([]FimProg, error) {
	spec, err := ossBTF.NewBTF()
	if err != nil {
		return nil, fmt.Errorf("GetCachedBTF error: %s", err)
	}
	if spec == nil {
		return nil, fmt.Errorf("GetCachedBTF returns nil")
	}

	var hooks []FimHook
	m := ""
	if mode == Observe {
		hooks = FimHooksObserve[:]
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

func probeTracingModifyReturn() error {
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachModifyReturn,
		AttachTo:   "security_file_mprotect",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachTracing(link.TracingOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported
	}
	return err
}

func probeLSM() error {
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "file_mprotect",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachLSM(link.LSMOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported
	}
	return err
}

func SupportEnforcement() bool {
	if probeTracingModifyReturn() == nil {
		return true
	}
	if probeLSM() == nil {
		if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
			return strings.Contains(string(lsm), "bpf")
		}
	}
	return false
}

//	int BPF_PROG(bprm_check, struct linux_binprm *bprm) {
//	    __u64 data;
//	    bpf_ima_file_hash(bprm->file, &data, sizeof(__u64));
//	    return 0;
//	}
//
// Binary code for the previous program
var testImaFileHashHelper = []byte{
	0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(u64 *)(r1 + 0)
	0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(u64 *)(r1 + 64)
	0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = r10
	0x07, 0x02, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, // r2 += -8
	0xb7, 0x03, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r3 = 8
	0x85, 0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, // call 193
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

func probeImaFileHashHelper() error {
	r := bytes.NewReader(testImaFileHashHelper)

	var insns asm.Instructions
	if err := insns.Unmarshal(r, binary.LittleEndian); err != nil {
		return fmt.Errorf("probeImaFileHashHelper: Cannot Unmarshal instructions: %w", err)
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.LSM,
		AttachType:   ebpf.AttachLSMMac,
		AttachTo:     "bprm_creds_for_exec",
		License:      "GPL",
		Flags:        unix.BPF_F_SLEEPABLE,
		Instructions: insns,
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachLSM(link.LSMOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported
	}
	return err
}

func SupportDigests() bool {
	if probeImaFileHashHelper() == nil {
		if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
			return strings.Contains(string(lsm), "bpf")
		}
	}
	return false
}

// returns the mode (i.e. Observe, Enforce etc.) and if the kernel supports file digests
func probeFileMode(s *fm.KernelSelectorState) (Mode, bool) {
	supportTracing := (probeTracingModifyReturn() == nil)
	logger.GetLogger().Infof("probeTracingModifyReturn() = %t", supportTracing)
	logger.GetLogger().Infof("HaveProgramType(ebpf.Tracing) = %t", (features.HaveProgramType(ebpf.Tracing) == nil))

	supportLSM := (probeLSM() == nil)
	enabledLSM := false
	if supportLSM {
		if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
			enabledLSM = strings.Contains(string(lsm), "bpf")
		}
	}
	supportImaFileHash := (probeImaFileHashHelper() == nil)
	logger.GetLogger().Infof("probeLSM() = %t probeImaFileHashHelper() = %t (enabled = %t)", supportLSM, supportImaFileHash, enabledLSM)
	logger.GetLogger().Infof("HaveProgramType(ebpf.LSM) = %t", (features.HaveProgramType(ebpf.LSM) == nil))

	digestSupport := supportImaFileHash && supportTracing

	if !s.NeedEnforcement() {
		return Observe, digestSupport
	}

	// If we have support for lsm and fmod_ret we prefer to use lsm.
	// For lsm we should also check that this is enabled.
	if supportLSM && enabledLSM {
		return EnforceLSM, digestSupport
	} else if supportTracing {
		return EnforceFmodRet, digestSupport
	}
	return EnforceNotSupported, digestSupport
}

func (k *observerFileSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()
	if len(spec.FileMonitoring.Paths) == 0 {
		if len(spec.FileMonitoring.PathsExclude) > 0 {
			return nil, fmt.Errorf("FileMonitoring requires more that one file_paths when file_paths_exclude is defined")
		}
		return nil, nil
	}

	forceLoad := false
	if val, ok := spec.FileMonitoring.Config["forceLoad"]; ok && val == "true" {
		forceLoad = true
	}
	enableExecDigests := false
	if val, ok := spec.FileMonitoring.Config["enableExecDigests"]; ok && val == "true" {
		enableExecDigests = true
	}

	configMaxWatchedDirs := uint32(maxWatchedDirs)
	if val, ok := spec.FileMonitoring.Config["maxWatchedDirs"]; ok {
		if v, err := strconv.ParseUint(val, 10, 32); err == nil {
			configMaxWatchedDirs = uint32(v)
			logger.GetLogger().Infof("FileMonitoring is starting with spec.file.file_config.maxWatchedDirs = %d", configMaxWatchedDirs)
		} else {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.maxWatchedDirs should be a number. User input: [%s]", val)
		}
	}

	configMaxWatchedFiles := uint32(maxWatchedFiles)
	if val, ok := spec.FileMonitoring.Config["maxWatchedFiles"]; ok {
		if v, err := strconv.ParseUint(val, 10, 32); err == nil {
			configMaxWatchedFiles = uint32(v)
			logger.GetLogger().Infof("FileMonitoring is starting with spec.file.file_config.maxWatchedFiles = %d", configMaxWatchedFiles)
		} else {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.maxWatchedFiles should be a number. User input: [%s]", val)
		}
	}

	if !forceLoad && !kernels.MinKernelVersion("4.19.0") {
		return nil, fmt.Errorf("FileMonitoring requires at least 4.19.0 version")
	}
	logger.GetLogger().Infof("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))

	if !spec.FileMonitoring.MonitorHostFiles && spec.FileMonitoring.PodSelector == nil {
		logger.GetLogger().Warnf("FileMonitoring policy with false monitorHostFile and nil PodSelector will not match anything")
	}

	selState, err := fm.InitKernelSelectorState(spec.FileMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse selectors: %w", err)
	}

	// start hubble-fgs-fs-scanner if it hasn't started yet
	if _, serr := os.Stat(fm.ScannerFifoPath); fsScannerCmd == nil || errors.Is(serr, os.ErrNotExist) {
		var err error
		fsScannerCmd, err = startFsScanner()
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring failed to start hubble-fgs-fs-scanner: %w", err)
		}
	}

	ioUringSupport := fm.SupportIoUring()
	logger.GetLogger().Infof("FileMonitoring kernel supports io_uring: %t", ioUringSupport)

	config := fileapi.FileConfigMapValue{
		HasSecurityPathRename: 1,
		PolicyId:              uint32(fid),
		MaxWatchedDirs:        configMaxWatchedDirs,
		MaxWatchedFiles:       configMaxWatchedFiles,
	}
	fileMode, digestSupport := probeFileMode(selState)
	if !enableExecDigests { // we explicitly disable digests if the user has not enabled them
		digestSupport = false
	}
	if enableExecDigests && !digestSupport { // the user enables exec digests but the kernel does not support them
		logger.GetLogger().Warn("FileMonitoring: User enables file digests but the kernel does not support them. Falling back to not using them.")
	}
	progs, err := findHooks(&config, fileMode, digestSupport, ioUringSupport)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring fails to find the appropriate hooks: %w", err)
	}
	return addFileMonitoringSensor(policy, spec.FileMonitoring, progs, config, selState)
}

func loadProbe(args sensors.LoadProbeArgs) error {
	v, ok := args.Load.LoaderData.(FimLoaderData)
	if !ok {
		return fmt.Errorf("type of LoaderData does not match FimLoaderData")
	}

	switch v.tp {
	case "kprobe", "kretprobe":
		return program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	case "fentry", "fexit", "fmod_ret":
		return program.LoadTracingProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	case "lsm", "lsm.s":
		return program.LoadLSMProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	default:
		return fmt.Errorf("file: %s programs are not supported", v.tp)
	}
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}

func (k *observerFileExecSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	if !policy.TpSpec().FileExecMonitoring.Enable {
		return nil, nil
	}

	var progs []*program.Program
	var maps []*program.Map
	tpid := atomic.AddUint32(&pol.SensorExecCounter, 1)
	name := fmt.Sprintf("fim_exec_sensor_%d", tpid)
	spec := policy.TpSpec()

	// having support for bpf_ima_file_hash helper means that we have everything that
	// we need to enable process_file_exec events
	if !SupportDigests() {
		return nil, fmt.Errorf("FileExecMonitoring is not supported in this kernel")
	}

	fimProgs := make([]FimProg, 0)
	for _, h := range FileExecHooksLsmDigests {
		if len(h.prog) != 1 {
			return nil, fmt.Errorf("FileExecMonitoring has more than one function prototypes per hook")
		}
		fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(h.prog[0].progName), h.prog[0].progSection})
	}

	selState, err := fm.InitKernelExecSelectorState(spec.FileExecMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileExecMonitoring failed to parse selectors: %w", err)
	}

	defaultAction, err := fm.GetActions(spec.FileExecMonitoring.DefaultActions)
	if err != nil {
		return nil, fmt.Errorf("FileExecMonitoring failed to parse default actions: %s", err)
	}

	// Block action results also in a post. We can introduce
	// support for nopost later if needed.
	if defaultAction&fm.FileOperationTypeBlock != 0 {
		defaultAction |= fm.FileOperationTypePost
	}

	config := fileapi.FileExecConfigMapValue{
		PolicyId:      uint32(fid),
		NumSelectors:  selState.GetNumSelectors(),
		DefaultAction: defaultAction,
	}

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			sensors.PathJoin(name, fmt.Sprintf("%s_%s", strings.Replace(h.tp, ".", "_", -1), h.name)),
			"file_exec_monitoring")
		load.SetLoaderData(FimLoaderData{
			s:  selState,
			tp: h.tp,
		})
		load.MaxEntriesInnerMap = map[string]uint32{
			"tg_mb_paths":       uint32(selState.MatchBinariesPathsMaxEntries()),
			"file_digests_maps": fm.GetMaxInnerEntriesDigestsMap(selState),
		}

		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "tg_mb_sel_opts",
				Load: func(outerMap *ebpf.Map, index uint32) error {
					return fm.PopulateMatchBinariesMaps(selState, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "tg_mb_paths",
				Load: func(outerMap *ebpf.Map, index uint32) error {
					return fm.PopulateMatchBinariesPathsMaps(selState, name, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "file_digests_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileDigestsMap(m, selState, name); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_capabilities_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileCapabilitiesMap(m, selState); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_namespaces_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileNamespacesMap(m, selState); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_actions_map",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileActionsMap(m, selState); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_exec_config_map",
				Load: func(m *ebpf.Map, index uint32) error {
					return m.Update(uint32(0), config, ebpf.UpdateAny)
				},
			},
		}

		for _, m := range []string{
			"exec_retprobe_map",
			"file_exec_config_map",
			"tg_mb_sel_opts",
			"tg_mb_paths",
			"file_digests_maps",
			"file_capabilities_map",
			"file_namespaces_map",
			"file_actions_map",
			"file_exec_stats_map",
		} {
			maps = append(maps, program.MapBuilderPin(m, sensors.PathJoin(name, m), load))
		}
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileExecSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}
