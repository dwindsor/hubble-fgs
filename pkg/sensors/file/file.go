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
	"github.com/cilium/tetragon/pkg/bpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
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
	FimHooks = [...]FimHook{
		{"kprobe", "vfs_fallocate", []FimFunc{{"vfs_fallocate(struct file*, int, loff_t, loff_t)", "bpf_vfs_fallocate.o", "vfs_fallocate"}}},
		{"kprobe", "filemap_fault", []FimFunc{{"filemap_fault(struct vm_fault*)", "bpf_filemap_fault.o", "filemap_fault"}}},
		{"kprobe", "filemap_map_pages", []FimFunc{{"filemap_map_pages(struct vm_fault*, int, int)", "bpf_filemap_map_pages.o", "filemap_map_pages"}}},
		{"kprobe", "filemap_page_mkwrite", []FimFunc{{"filemap_page_mkwrite(struct vm_fault*)", "bpf_filemap_page_mkwrite.o", "filemap_page_mkwrite"}}},
		{"kprobe", "rw_verify_area", []FimFunc{{"rw_verify_area(int, struct file*, const loff_t*, size_t)", "bpf_rw_verify_area.o", "rw_verify_area"}}},
		{"kprobe", "vfs_unlink", []FimFunc{
			{"vfs_unlink(struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/419"},
			{"vfs_unlink(struct user_namespace*, struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/512"},
		}},
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open"}}},
		{"kprobe", "vfs_rmdir", []FimFunc{
			{"vfs_rmdir(struct inode*, struct dentry*)", "bpf_vfs_rmdir.o", "vfs_rmdir/419"},
			{"vfs_rmdir(struct user_namespace*, struct inode*, struct dentry*)", "bpf_vfs_rmdir.o", "vfs_rmdir/512"},
		}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir"},
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
		{"kprobe", "do_truncate", []FimFunc{
			{"do_truncate(struct dentry*, loff_t, int, struct file*)", "bpf_do_truncate.o", "do_truncate/419"},
			{"do_truncate(struct user_namespace*, struct dentry*, loff_t, int, struct file*)", "bpf_do_truncate.o", "do_truncate/512"},
		}},
		{"kprobe", "chmod_common", []FimFunc{{"chmod_common(const struct path*, umode_t)", "bpf_chmod_common.o", "chmod_common"}}},
		{"kprobe", "chown_common", []FimFunc{{"chown_common(const struct path*, uid_t, gid_t)", "bpf_chown_common.o", "chown_common"}}},
	}

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"rename_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_file_alloc",
		"hash_map_dir_alloc",
		"file_names_map",
		"file_ops_map",
		"file_config_map",
	}
)

func TerminateFsScanner() error {
	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
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
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.TracingPolicyInit", &f, &struct{}{}); err != nil {
		return err
	}
	return nil
}

func RenameFsScanner(p string, m string, o uint32, a uint32, pin string, cid string) error {
	f := fm.FsScannerRename{
		Path:        p,
		MapDir:      m,
		Op:          o,
		Action:      a,
		PinPath:     pin,
		ContainerID: cid,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.RenameDir", &f, &struct{}{}); err != nil {
		return err
	}
	return nil
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
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.TracingPolicyContainerInit", &f, &struct{}{}); err != nil {
		return err
	}
	return nil
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
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.TracingPolicyContainerDestroy", &f, &struct{}{}); err != nil {
		return err
	}
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

	args := []string{"-hostMntNs", strconv.FormatUint(uint64(namespace.GetPidNsInode(1, "mnt")), 10), "-scannerFifoPath", fm.ScannerFifoPath}
	if option.Config.Debug {
		args = append([]string{"-debug"}, args...)
	}

	level, levelOk := option.Config.LogOpts["level"]
	if levelOk {
		args = append([]string{"-logLevel", level}, args...)
	}

	format, formatOk := option.Config.LogOpts["format"]
	if formatOk {
		args = append([]string{"-logFormat", format}, args...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	fsScannerCmd := exec.CommandContext(ctx, path.Join(option.Config.HubbleLib, "hubble-fgs-fs-scanner"), args...)
	fsScannerCancelFnMtx.Lock()
	fsScannerCancelFn = cancel
	fsScannerCancelFnMtx.Unlock()

	logger.GetLogger().WithField("args", fsScannerCmd.Args).Info("Agent starting hubble-fgs-fs-scanner")

	fsScannerCmd.Env = append(fsScannerCmd.Env, fmt.Sprintf("TETRAGON_PROCFS=%s", option.Config.ProcFS))
	fsScannerCmd.Stdout = os.Stdout
	fsScannerCmd.Stderr = os.Stderr

	if err := fsScannerCmd.Start(); err != nil {
		return nil, err
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
			logger.GetLogger().WithError(err).Warnf("fsScannerCmd.Wait() failed with '%s'", err)
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

var (
	fileMonitoringTable = fimTable{
		mp: make(map[uint32]*fileMonitoring),
	}

	sensorCounter uint32
)

type fileMonitoring struct {
	Spec          *v1alpha1.FileSpec
	pinPathPrefix string
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
	cleanupMap[uint32, uint32](tc.pinPathPrefix, "file_names_map")
	cleanupMap[uint32, uint32](tc.pinPathPrefix, "file_ops_map")

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
		if err := addFilters(lpmMap, str, fm.FilterMatch); err != nil {
			return fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range spec.PathsExclude {
		if err := addFilters(lpmMap, str, fm.FilterIgnore); err != nil {
			return fmt.Errorf("failed to add ExcludePath: %w", err)
		}
	}

	if !spec.OnlyPodFiles {
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

	// special (zero) value to store the policy index
	if err := fm.AddFilePath(fileHandle, fileapi.HashMapFileKey{}, fileapi.HashMapFileVal{
		Action: uint32(id),
	}); err != nil {
		return fmt.Errorf("failed to add entry <ino,dev> = <0,0> : %w", err)
	}

	selMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_names_map"))
	selHandle, err := ebpf.LoadPinnedMap(selMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selMapPath)
	}
	defer selHandle.Close()

	sel, err := fm.InitKernelSelectorState(spec.Selectors)
	if err != nil {
		return fmt.Errorf("failed to initialize kernel selector state")
	}

	if err := fm.GenerateFileNamesMap(selHandle, sel); err != nil {
		return fmt.Errorf("failed to populate file_names_map")
	}

	if err := fm.UpdateNamesMap(mapDir, sel); err != nil {
		return fmt.Errorf("failed to update names_map")
	}

	selOpsMapPath := filepath.Join(mapDir, sensors.PathJoin(tc.pinPathPrefix, "file_ops_map"))
	selOpsHandle, err := ebpf.LoadPinnedMap(selOpsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selOpsHandle.Close()

	if err := fm.GenerateFileOpsMap(selOpsHandle, sel); err != nil {
		return fmt.Errorf("failed to populate file_ops_map")
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
		uuid_str = u.String()
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
		filemetrics.FileTotalErrors().Inc()
		return nil, fmt.Errorf("Failed to read file operation: %w", err)
	}

	str := string(m.Path.Str[:])
	if uint32(len(str)) > m.Path.Size {
		str = str[:m.Path.Size]
	}

	cid := ""
	if m.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		cid = string(m.Path.ContainerID[:])
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
		Offset:      m.Offset,
		Size:        m.Size,
		MntNs:       m.MntNs,
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
		filemetrics.FileTotalErrors().Inc()
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}

	srcDir := string(m.Src.Path.Dir[:])
	if m.Src.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "<UNRESOLVED>"
	} else if uint32(len(srcDir)) > m.Src.Path.DirSize {
		srcDir = srcDir[:m.Src.Path.DirSize]
	}

	srcName := string(m.Src.Path.Name[:])
	if uint32(len(srcName)) > m.Src.Path.NameSize {
		srcName = srcName[:m.Src.Path.NameSize]
	}

	srcCid := ""
	if m.Src.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		srcCid = string(m.Src.Path.ContainerID[:])
	}

	dstDir := string(m.Dst.Path.Dir[:])
	if m.Dst.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "<UNRESOLVED>"
	} else if uint32(len(dstDir)) > m.Dst.Path.DirSize {
		dstDir = dstDir[:m.Dst.Path.DirSize]
	}

	dstName := string(m.Dst.Path.Name[:])
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

		s, err := fileMonitoringTable.getFIM(m.TcId)
		if err != nil {
			filemetrics.FileTotalErrors().Inc()
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

		if err := RenameFsScanner(path, option.Config.MapDir, op, action, s.pinPathPrefix, renameCid); err != nil {
			filemetrics.FileTotalErrors().Inc()
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
		MntNs: m.MntNs,
		Flags: m.Flags,
	}

	return []observer.Event{unix}, nil
}

func addFilter(handle *ebpf.Map, filter string, val fileapi.LPMMapValue) error {
	var k fileapi.LPMMapKey

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	var exVal fileapi.LPMMapValue
	if err := handle.Lookup(k, &exVal); err == nil { // key already exists
		// already exists with value FilterMatch, do not update to FilterIgnore.
		if exVal == fm.FilterMatch {
			return nil
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

		if str == "/" { // reached root fs - nothing more to do
			return nil
		}

		// remove the rightmost path component
		str, _ = filepath.Split(strings.TrimSuffix(str, "/"))
	}
}

type FimLoaderData struct {
	s *fm.KernelSelectorState
}

func addFileMonitoringSensor(tcID uint32, kprobes v1alpha1.FileSpec, btfBaseFile string, fimProgs []FimProg, config fileapi.FileConfigMapValue, sel *fm.KernelSelectorState) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var err error

	name := fmt.Sprintf("fim_sensor_%d", tcID)
	e := &fileMonitoring{
		Spec:          &kprobes,
		pinPathPrefix: name,
	}
	fileMonitoringTable.addFIM(tcID, e)

	l := logger.GetLogger()
	mapDir := bpf.MapPrefixPath()
	os.Mkdir(mapDir, os.ModeDir)

	ms := &ebpf.MapSpec{
		Name:       "lpm_trie_map_alloc",
		Type:       bpf.BPF_MAP_TYPE_LPM_TRIE,
		KeySize:    uint32(unsafe.Sizeof(fileapi.LPMMapKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.LPMMapValue(0))),
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
		if err := addFilters(lpmMap, str, fm.FilterMatch); err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range kprobes.PathsExclude {
		if err := addFilters(lpmMap, str, fm.FilterIgnore); err != nil {
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

	// special (zero) value to store the policy index
	tableKey := fileapi.HashMapFileKey{}

	tableVal := fileapi.HashMapFileVal{
		Action: uint32(tcID),
	}

	if err := fm.AddFilePath(fileHandle, tableKey, tableVal); err != nil {
		return nil, fmt.Errorf("failed to add entry <ino,dev> = <0,0> : %w", err)
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

	if !kprobes.OnlyPodFiles {
		if err := TracingPolicyInitFsScanner(kprobes, option.Config.MapDir, e.pinPathPrefix); err != nil {
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
			logger.GetLogger().WithError(err).Warnf("TracingPolicyInitContainerFsScanner failed")
		}
	}

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			sensors.PathJoin(e.pinPathPrefix, fmt.Sprintf("%s_%s", h.tp, h.name)),
			"file_monitoring")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		load.SetLoaderData(FimLoaderData{
			s: sel,
		})
		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "file_names_map",
				Load: func(m *ebpf.Map, index uint32) error {
					return fm.GenerateFileNamesMap(m, sel)
				},
			},
			{
				Index: 0,
				Name:  "file_ops_map",
				Load: func(m *ebpf.Map, index uint32) error {
					return fm.GenerateFileOpsMap(m, sel)
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
		UnloadHook: func() error {
			fileMonitoringTable.rmFIM(tcID)
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

func findHooks(config *fileapi.FileConfigMapValue) ([]FimProg, error) {
	spec := ossBTF.GetCachedBTF()
	if spec == nil {
		return nil, fmt.Errorf("GetCachedBTF returns nil")
	}

	fimProgs := make([]FimProg, 0)
	for _, h := range FimHooks {
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

// PolicyHandler (called on init)
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
	if !forceLoad && !kernels.MinKernelVersion("4.19.0") {
		logger.GetLogger().Warnf("FileMonitoring requires at least 4.19.0 version")
		return nil, nil
	}
	logger.GetLogger().Infof("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))

	selState, err := fm.InitKernelSelectorState(spec.FileMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse selectors")
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
	progs, err := findHooks(&config)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("FileMonitoring fails to find the appropriate hooks")
		return nil, nil
	}
	tcID := atomic.AddUint32(&sensorCounter, 1)
	return addFileMonitoringSensor(tcID, spec.FileMonitoring, option.Config.BTF, progs, config, selState)
	return nil, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k *observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	var err error

	// this should be done after initializing the base sensor
	loadProbeInit.Do(func() {
		// get the pinPathPrefix
		v, ok := args.Load.LoaderData.(FimLoaderData)
		if ok {
			err = fm.UpdateNamesMap(args.MapDir, v.s)
		} else {
			err = fmt.Errorf("type of LoaderData does not match FimLoaderData")
		}
	})
	if err != nil {
		return err
	}
	return program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
}
