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

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/grpc/file"
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

type FimFunc struct {
	proto, progName string
}

type FimHook struct {
	tp, name string
	prog     []FimFunc
}

type FimProg struct {
	tp, name, progName string
}

var (
	FimHooks = [...]FimHook{
		{"kprobe", "vfs_fallocate", []FimFunc{{"vfs_fallocate(struct file*, int, loff_t, loff_t)", "bpf_vfs_fallocate.o"}}},
		{"kprobe", "filemap_fault", []FimFunc{{"filemap_fault(struct vm_fault*)", "bpf_filemap_fault.o"}}},
		{"kprobe", "filemap_map_pages", []FimFunc{{"filemap_map_pages(struct vm_fault*, int, int)", "bpf_filemap_map_pages.o"}}},
		{"kprobe", "filemap_page_mkwrite", []FimFunc{{"filemap_page_mkwrite(struct vm_fault*)", "bpf_filemap_page_mkwrite.o"}}},
		{"kprobe", "rw_verify_area", []FimFunc{{"rw_verify_area(int, struct file*, const loff_t*, size_t)", "bpf_rw_verify_area.o"}}},
		{"kprobe", "security_path_unlink", []FimFunc{{"security_path_unlink(const struct path*, struct dentry*)", "bpf_security_path_unlink.o"}}},
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o"}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o"}}},
		{"kprobe", "vfs_rmdir", []FimFunc{
			{"vfs_rmdir(struct inode*, struct dentry*)", "bpf_vfs_rmdir.o"},
			{"vfs_rmdir(struct user_namespace*, struct inode*, struct dentry*)", "bpf_vfs_rmdir_v512.o"},
		}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir_v512.o"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o"},
		}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o"}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o"}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o"},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename_v512.o"},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o"},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o"},
		}},
	}

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"rename_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_file_alloc",
		"hash_map_dir_alloc",
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

func RenameFsScanner(p string, m string, o uint32, a uint32, pin string) error {
	f := fm.FsScannerRename{
		Path:    p,
		MapDir:  m,
		Op:      o,
		Action:  a,
		PinPath: pin,
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

func startFsScanner() (*exec.Cmd, error) {
	if fm.ScannerFifoPath == "" {
		if option.Config.EnableK8s {
			fm.ScannerFifoPath = path.Join(fm.K8sScannerFifoPath, fm.ScannerFifoName)
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

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterSpecHandlerAtInit(file.name, file)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE, handleFileOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_RENAME, handleFileRenameOps)
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
		return nil, fmt.Errorf("Failed to read file operation: %w", err)
	}

	str := string(m.Path.Str[:])
	if uint32(len(str)) > m.Path.Size {
		str = str[:m.Path.Size]
	}
	unix := &file.MsgFileEventUnix{
		Common:     m.Common,
		ProcessKey: m.ProcessKey,
		Path:       str,
		Action:     m.Action,
		Hook:       m.Hook,
		Timestamp:  m.Timestamp,
		Imode:      uint32(m.Imode),
		Uid:        m.Uid,
		Gid:        m.Gid,
		Ino:        m.Ino,
		Fs:         createFsInfoUnix(m.Fs),
		ParentIno:  m.ParentIno,
		ParentFs:   createFsInfoUnix(m.ParentFs),
		Offset:     m.Offset,
		Size:       m.Size,
		MntNs:      m.MntNs,
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
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}
	srcDir := string(m.Src.Path.Dir[:])
	if uint32(len(srcDir)) > m.Src.Path.DirSize {
		srcDir = srcDir[:m.Src.Path.DirSize]
	}

	srcName := string(m.Src.Path.Name[:])
	if uint32(len(srcName)) > m.Src.Path.NameSize {
		srcName = srcName[:m.Src.Path.NameSize]
	}

	dstDir := string(m.Dst.Path.Dir[:])
	if uint32(len(dstDir)) > m.Dst.Path.DirSize {
		dstDir = dstDir[:m.Dst.Path.DirSize]
	}

	dstName := string(m.Dst.Path.Name[:])
	if uint32(len(dstName)) > m.Dst.Path.NameSize {
		dstName = dstName[:m.Dst.Path.NameSize]
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
			return nil, fmt.Errorf("failed to get fim table index: %w", err)
		}

		if err := RenameFsScanner(path, option.Config.MapDir, op, action, s.pinPathPrefix); err != nil {
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
			Path:      filepath.Join(srcDir, srcName),
			Ino:       m.Src.Ino,
			Fs:        createFsInfoUnix(m.Src.Fs),
			ParentIno: m.Src.ParentIno,
			ParentFs:  createFsInfoUnix(m.Src.ParentFs),
		},
		Dst: file.MsgRenameElemUnix{
			Path:      filepath.Join(dstDir, dstName),
			Ino:       m.Dst.Ino,
			Fs:        createFsInfoUnix(m.Dst.Fs),
			ParentIno: m.Dst.ParentIno,
			ParentFs:  createFsInfoUnix(m.Dst.ParentFs),
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

	err := handle.Update(k, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func addFileMonitoringSensor(tcID uint32, kprobes v1alpha1.FileSpec, btfBaseFile string, fimProgs []FimProg) (*sensors.Sensor, error) {
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
		if err := addFilter(lpmMap, str, fm.FilterMatch); err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range kprobes.PathsExclude {
		if err := addFilter(lpmMap, str, fm.FilterIgnore); err != nil {
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

	if err := TracingPolicyInitFsScanner(kprobes, option.Config.MapDir, e.pinPathPrefix); err != nil {
		l.WithError(err).Warnf("TracingPolicyInitFsScanner failed!")
	}

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.name),
			sensors.PathJoin(e.pinPathPrefix, fmt.Sprintf("%s_%s", h.tp, h.name)),
			"kprobe")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		progs = append(progs, load)

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

func findHooks() ([]FimProg, error) {
	spec := ossBTF.GetCachedBTF()
	if spec == nil {
		return nil, fmt.Errorf("GetCachedBTF returns nil")
	}

	fimProgs := make([]FimProg, 0)
	for _, h := range FimHooks {
		kretprobe := (h.tp == "kretprobe")
		p, err := fgsBTF.GetFuncProto(spec, h.name, kretprobe)
		if err != nil {
			return nil, fmt.Errorf("GetFuncProto failed: %w", err)
		}

		progFound := false
		for _, f := range h.prog {
			if f.proto == p {
				progFound = true
				fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(f.progName)})
				break
			}
		}
		if !progFound {
			return nil, fmt.Errorf("function %s has different prototype in BTF (BTF: %s) compared to FIM", h.name, p)
		}
	}

	return fimProgs, nil
}

// SpecHandler() (called on init)
func (k *observerFileSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	if len(spec.FileMonitoring.Paths) == 0 && len(spec.FileMonitoring.PathsExclude) > 0 {
		logger.GetLogger().Warnf("FileMonitoring requires more that one file_paths when file_paths_exclude is defined")
		return nil, nil
	}
	if len(spec.FileMonitoring.Paths) > 0 {
		forceLoad := false
		if val, ok := spec.FileMonitoring.Config["forceLoad"]; ok && val == "true" {
			forceLoad = true
		}
		if !forceLoad && !kernels.MinKernelVersion("4.19.0") {
			logger.GetLogger().Warnf("FileMonitoring requires at least 4.19.0 version")
			return nil, nil
		}
		logger.GetLogger().Infof("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))

		// start hubble-fgs-fs-scanner if it hasn't started yet
		if _, serr := os.Stat(fm.ScannerFifoPath); fsScannerCmd == nil || errors.Is(serr, os.ErrNotExist) {
			var err error
			fsScannerCmd, err = startFsScanner()
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Failed to start hubble-fgs-fs-scanner")
				return nil, nil
			}

		}

		progs, err := findHooks()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("FileMonitoring fails to find the appropriate hooks")
			return nil, nil
		}
		tcID := atomic.AddUint32(&sensorCounter, 1)
		return addFileMonitoringSensor(tcID, spec.FileMonitoring, option.Config.BTF, progs)
	}
	return nil, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k *observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	// all is done in SpecHandler
	return nil
}
