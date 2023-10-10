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
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
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
var loadProbeInit sync.Once

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

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"rename_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_file_alloc",
		"hash_map_dir_alloc",
		"file_names_maps",
		"file_ops_maps",
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

func TracingPolicyInitFsScanner(s v1alpha1.FileSpec, m string, pin string) error {
	f := fm.FsScannerInit{
		Spec:    s,
		MapDir:  m,
		PinPath: pin,
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

func TracingPolicyInitContainerFsScanner(containerID, podNs, podName, rootDir string) error {
	pinPath, spec := fileMonitoringTable.getValuesFIM()
	f := fm.FsScannerContainerInit{
		Spec:        spec,
		PinPath:     pinPath,
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
	pinPath, _ := fileMonitoringTable.getValuesFIM()
	f := fm.FsScannerContainerDestroy{
		MapDir:      option.Config.MapDir,
		PinPath:     pinPath,
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

	args := []string{fmt.Sprintf("%s/1/ns/mnt", option.Config.ProcFS), execName, "-hostMntNs", strconv.FormatUint(uint64(namespace.GetPidNsInode(1, "mnt")), 10), "-scannerFifoPath", fm.ScannerFifoPath}

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
		logger.GetLogger().Warnf("hubble-fgs-fs-scanner fifo does not exist [retry = %d]", retry)
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

var (
	fileMonitoringTable = fimTable{
		mp: make(map[uint32]*fileMonitoring),
	}

	sensorCounter     uint32
	sensorExecCounter uint32
)

type fileMonitoring struct {
	Spec          *v1alpha1.FileSpec
	pinPathPrefix string
	tpName        string
	tpRules       map[int]string
}

type fimTable struct {
	mu sync.Mutex
	mp map[uint32]*fileMonitoring
}

func (t *fimTable) addFIM(id uint32, tp *fileMonitoring) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mp[id] = tp
}

func (t *fimTable) getFIM(id uint32) (*fileMonitoring, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, ok := t.mp[id]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("fim table: invalid id:%d", id)
}

func (t *fimTable) getTpName(id uint32) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, ok := t.mp[id]; ok {
		return val.tpName
	}
	return "<unresolved_policy>"
}

func (t *fimTable) getTpRule(tpID, ruleID uint32) string {
	val, err := t.getFIM(tpID)
	if err != nil {
		return "<unresolved_policy>"
	}
	rl, ok := val.tpRules[int(ruleID)]
	if !ok {
		return "<unresolved_rule>"
	}
	return rl
}

func (t *fimTable) rmFIM(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.mp, id)
}

func (t *fimTable) getValuesFIM() ([]string, []v1alpha1.FileSpec) {
	var pinPaths []string
	var specs []v1alpha1.FileSpec
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, elem := range t.mp {
		pinPaths = append(pinPaths, elem.pinPathPrefix)
		specs = append(specs, *elem.Spec)
	}
	return pinPaths, specs
}

func ClearFIMTracingPolicies() {
	fileMonitoringTable = fimTable{
		mp: make(map[uint32]*fileMonitoring),
	}
}

// only for testing
// remove all entries of a map
func cleanupMap[K any, V any](pinPathPrefix string, mapName string) (int, error) {
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(pinPathPrefix, mapName))
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	var key K
	var val V
	count := 0
	for {
		entries := handle.Iterate()
		keyFound := false
		for entries.Next(&key, &val) {
			if err := handle.Delete(key); err == nil {
				count++
			}
			keyFound = true
			break

		}
		if !keyFound {
			break
		}
	}

	return count, nil
}

// only for testing
// remove all entries of all FIM maps
func cleanupFIMMaps(id uint32) error {
	var tc *fileMonitoring
	if x, found := fileMonitoringTable.mp[id]; found {
		tc = x
	} else {
		return fmt.Errorf("tracing policy with ID=%d does not exist", id)
	}

	cleanupMap[fileapi.LPMMapKey, fileapi.LPMMapValue](tc.pinPathPrefix, "lpm_trie_map_alloc")
	cleanupMap[fileapi.HashMapFileKey, fileapi.HashMapFileVal](tc.pinPathPrefix, "hash_map_file_alloc")
	cleanupMap[fileapi.HashMapFileKey, fileapi.HashMapFileVal](tc.pinPathPrefix, "hash_map_dir_alloc")
	cleanupMap[uint32, uint32](tc.pinPathPrefix, "file_names_maps")
	cleanupMap[uint32, uint32](tc.pinPathPrefix, "file_ops_maps")
	cleanupMap[fileapi.DigestKey, uint32](tc.pinPathPrefix, "file_digests_maps")
	cleanupMap[uint32, uint32](tc.pinPathPrefix, "file_actions_map")

	return nil
}

// only for testing
// generate the contents of FIM maps (the maps already exist and are empty)
func generateFIMMaps(id uint32, spec *v1alpha1.FileSpec) error {
	var tc *fileMonitoring
	if x, found := fileMonitoringTable.mp[id]; found {
		tc = x
	} else {
		return fmt.Errorf("tracing policy with ID=%d does not exist", id)
	}

	tc.Spec = spec
	mapDir := bpf.MapPrefixPath()
	mapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "lpm_trie_map_alloc"))
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
		if err := TracingPolicyInitFsScanner(*spec, mapDir, tc.pinPathPrefix); err != nil {
			return err
		}
	}

	fileMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "hash_map_file_alloc"))
	fileHandle, err := ebpf.LoadPinnedMap(fileMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", fileMapPath)
	}
	defer fileHandle.Close()

	selMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_names_maps"))
	selHandle, err := ebpf.LoadPinnedMap(selMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selMapPath)
	}
	defer selHandle.Close()

	sel, err := fm.InitKernelSelectorState(spec.Selectors)
	if err != nil {
		return fmt.Errorf("failed to initialize kernel selector state: %w", err)
	}

	if err := fm.GenerateFileNamesMap(selHandle, sel, tc.pinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_names_maps: %w", err)
	}

	if err := fm.UpdateNamesMap(mapDir, sel); err != nil {
		return fmt.Errorf("failed to update names_map")
	}

	selOpsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_ops_maps"))
	selOpsHandle, err := ebpf.LoadPinnedMap(selOpsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selOpsHandle.Close()

	if err := fm.GenerateFileOpsMap(selOpsHandle, sel, tc.pinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_ops_maps: %w", err)
	}

	selDigestsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_digests_maps"))
	selDigestsHandle, err := ebpf.LoadPinnedMap(selDigestsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selDigestsHandle.Close()

	if err := fm.GenerateFileDigestsMap(selDigestsHandle, sel, tc.pinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_digests_maps: %w", err)
	}

	selActionsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_actions_map"))
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
	fileMonitoringTable.mu.Lock()
	defer fileMonitoringTable.mu.Unlock()

	if len(fileMonitoringTable.mp) != 1 {
		return fmt.Errorf("file sensor has more than one tracing policies")
	}

	tcID := uint32(0)
	for key := range fileMonitoringTable.mp {
		tcID = key
	}

	if err := cleanupFIMMaps(tcID); err != nil {
		return err
	}

	return generateFIMMaps(tcID, spec)
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
		TpName:      fileMonitoringTable.getTpName(m.TpId),
		TpRule:      fileMonitoringTable.getTpRule(m.TpId, m.RuleID),
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

		s, err := fileMonitoringTable.getFIM(m.TpId)
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

		if err := RenameFsScanner(path, option.Config.MapDir, op, action, s.pinPathPrefix, renameCid, m.RuleID); err != nil {
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
		TpName:    fileMonitoringTable.getTpName(m.TpId),
		TpRule:    fileMonitoringTable.getTpRule(m.TpId, m.RuleID),
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

	config.TpId = atomic.AddUint32(&sensorCounter, 1)
	name := fmt.Sprintf("fim_sensor_%d", config.TpId)
	e := &fileMonitoring{
		Spec:          &kprobes,
		pinPathPrefix: name,
		tpName:        policy.TpName(),
		tpRules:       make(map[int]string),
	}
	// Add rules from file_paths with a unique number assosciated to each of them.
	// No need to add file_paths_exclude as we will never get an event from these.
	for i, p := range kprobes.Paths {
		e.tpRules[i] = p
	}
	fileMonitoringTable.addFIM(config.TpId, e)

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

	lpmPinPath := path.Join(mapDir, sensors.PathJoin(e.pinPathPrefix, "lpm_trie_map_alloc"))
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
		MaxEntries: maxWatchedFiles,
		Flags:      0,
	}

	fileHandle, err := ebpf.NewMapWithOptions(hs, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}
	defer fileHandle.Close()

	filePinPath := path.Join(mapDir, sensors.PathJoin(e.pinPathPrefix, "hash_map_file_alloc"))
	// remove the map if already exists, otheriwse Pin() will fail
	if _, err := os.Stat(filePinPath); err == nil {
		os.Remove(filePinPath)
	}
	if err := fileHandle.Pin(filePinPath); err != nil {
		return nil, fmt.Errorf("failed fileHandle.Pin: %w", err)
	}

	ds := &ebpf.MapSpec{
		Name:       "hash_map_dir_alloc",
		Type:       bpf.BPF_MAP_TYPE_HASH,
		KeySize:    uint32(unsafe.Sizeof(fileapi.HashMapFileKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.HashMapFileVal{})),
		MaxEntries: maxWatchedDirs,
		Flags:      0,
	}

	dirHandle, err := ebpf.NewMapWithOptions(ds, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}
	defer dirHandle.Close()

	dirPinPath := path.Join(mapDir, sensors.PathJoin(e.pinPathPrefix, "hash_map_dir_alloc"))
	// remove the map if already exists, otheriwse Pin() will fail
	if _, err := os.Stat(dirPinPath); err == nil {
		os.Remove(dirPinPath)
	}
	if err := dirHandle.Pin(dirPinPath); err != nil {
		return nil, fmt.Errorf("failed dirHandle.Pin: %w", err)
	}

	if kprobes.MonitorHostFiles {
		if err := TracingPolicyInitFsScanner(kprobes, option.Config.MapDir, e.pinPathPrefix); err != nil {
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
		if err := TracingPolicyInitContainerFsScanner(i.cid, i.namespace, i.name, i.root); err != nil {
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
			sensors.PathJoin(e.pinPathPrefix, fmt.Sprintf("%s_%s", strings.Replace(h.tp, ".", "_", -1), h.name)),
			"file_monitoring")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		load.SetLoaderData(FimLoaderData{
			s:  sel,
			tp: h.tp,
		})
		load.MaxEntriesInnerMap = map[string]uint32{
			"file_names_maps":   fm.GetMaxInnerEntriesNamesMap(sel),
			"file_ops_maps":     fm.GetMaxInnerEntriesOpsMap(sel),
			"file_digests_maps": fm.GetMaxInnerEntriesDigestsMap(sel),
		}
		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "file_names_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileNamesMap(m, sel, e.pinPathPrefix); err != nil {
						return fmt.Errorf("file_names_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_ops_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileOpsMap(m, sel, e.pinPathPrefix); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_digests_maps",
				Load: func(m *ebpf.Map, index uint32) error {
					if err := fm.GenerateFileDigestsMap(m, sel, e.pinPathPrefix); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
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
				program.MapBuilderPin(m, sensors.PathJoin(e.pinPathPrefix, m), load),
			)
		}

		for _, m := range SharedMaps {
			maps = append(
				maps,
				program.MapBuilderPin(m, sensors.PathJoin(e.pinPathPrefix, m), load),
			)
		}
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
		PreUnloadHook: func() error {
			fileMonitoringTable.rmFIM(config.TpId)
			return nil
		},
	}, nil
}

func fixProgName(p string) string {
	if p == "bpf_vfs_rename.o" && kernels.IsKernelVersionLessThan("5.3.0") {
		return "bpf_vfs_rename_v419.o"
	}
	return p
}

func findHooks(config *fileapi.FileConfigMapValue, mode Mode, digestSupport bool) ([]FimProg, error) {
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
	} else {
		return nil, fmt.Errorf("unknown mode in findHooks [%d]", mode)
	}
	logger.GetLogger().Infof("Loading file hooks for %s", m)

	fimProgs := make([]FimProg, 0)
	for _, h := range hooks {
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
			logger.GetLogger().Warnf("FileMonitoring requires more that one file_paths when file_paths_exclude is defined")
		}
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("file sensor does not implement policy filtering")
	}

	forceLoad := false
	if val, ok := spec.FileMonitoring.Config["forceLoad"]; ok && val == "true" {
		forceLoad = true
	}
	enableExecDigests := false
	if val, ok := spec.FileMonitoring.Config["enableExecDigests"]; ok && val == "true" {
		enableExecDigests = true
	}

	if !forceLoad && !kernels.MinKernelVersion("4.19.0") {
		logger.GetLogger().Warnf("FileMonitoring requires at least 4.19.0 version")
		return nil, nil
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
			logger.GetLogger().WithError(err).Warnf("Failed to start hubble-fgs-fs-scanner")
			return nil, nil
		}
	}

	config := fileapi.FileConfigMapValue{
		HasSecurityPathRename: 1,
	}
	fileMode, digestSupport := probeFileMode(selState)
	if !enableExecDigests { // we explicitly disable digests if the user has not enabled them
		digestSupport = false
	}
	if enableExecDigests && !digestSupport { // the user enables exec digests but the kernel does not support them
		logger.GetLogger().Warn("FileMonitoring: User enables file digests but the kernel does not support them. Falling back to not using them.")
	}
	progs, err := findHooks(&config, fileMode, digestSupport)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("FileMonitoring fails to find the appropriate hooks")
		return nil, nil
	}
	return addFileMonitoringSensor(policy, spec.FileMonitoring, progs, config, selState)
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k *observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	v, ok := args.Load.LoaderData.(FimLoaderData)
	if !ok {
		return fmt.Errorf("type of LoaderData does not match FimLoaderData")
	}

	// this should be done after initializing the base sensor
	var err error
	loadProbeInit.Do(func() {
		// get the pinPathPrefix
		err = fm.UpdateNamesMap(args.MapDir, v.s)
	})
	if err != nil {
		return err
	}

	if v.tp == "kprobe" || v.tp == "kretprobe" {
		return program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else if v.tp == "fentry" || v.tp == "fexit" || v.tp == "fmod_ret" {
		return program.LoadTracingProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else if v.tp == "lsm" || v.tp == "lsm.s" {
		return program.LoadLSMProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else {
		return fmt.Errorf("file: %s programs are not supported", v.tp)
	}
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
	tpid := atomic.AddUint32(&sensorExecCounter, 1)
	name := fmt.Sprintf("fim_exec_sensor_%d", tpid)

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

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			sensors.PathJoin(name, fmt.Sprintf("%s_%s", strings.Replace(h.tp, ".", "_", -1), h.name)),
			"file_exec_monitoring")
		load.SetLoaderData(FimLoaderData{
			s:  nil,
			tp: h.tp,
		})

		progs = append(progs, load)

		m := "exec_retprobe_map"
		maps = append(maps, program.MapBuilderPin(m, sensors.PathJoin(name, m), load))
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k *observerFileExecSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	v, ok := args.Load.LoaderData.(FimLoaderData)
	if !ok {
		return fmt.Errorf("type of LoaderData does not match FimLoaderData")
	}

	if v.tp == "kprobe" || v.tp == "kretprobe" {
		return program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else if v.tp == "fentry" || v.tp == "fexit" || v.tp == "fmod_ret" {
		return program.LoadTracingProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else if v.tp == "lsm" || v.tp == "lsm.s" {
		return program.LoadLSMProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	} else {
		return fmt.Errorf("file: %s programs are not supported", v.tp)
	}
}
