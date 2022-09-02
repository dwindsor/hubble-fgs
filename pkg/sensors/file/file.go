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
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/grpc/file"

	"github.com/google/uuid"
)

const (
	filterIgnore = 0
	filterMatch  = 1

	maxLPMpaths     = 4096
	maxWatchedDirs  = 128 * 1024 // 128K
	maxWatchedFiles = 128 * 1024 // 128K
)

var (
	dirMap  *ebpf.Map
	fileMap *ebpf.Map
	lpmMap  *ebpf.Map
)

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
		{"kprobe", "vfs_fallocate", []FimFunc{{"vfs_fallocate(struct file*, int, loff_t, loff_t)", "bpf_file.o"}}},
		{"kprobe", "filemap_fault", []FimFunc{{"filemap_fault(struct vm_fault*)", "bpf_file.o"}}},
		{"kprobe", "filemap_map_pages", []FimFunc{{"filemap_map_pages(struct vm_fault*, int, int)", "bpf_file.o"}}},
		{"kprobe", "filemap_page_mkwrite", []FimFunc{{"filemap_page_mkwrite(struct vm_fault*)", "bpf_file.o"}}},
		{"kprobe", "rw_verify_area", []FimFunc{{"rw_verify_area(int, struct file*, const loff_t*, size_t)", "bpf_file.o"}}},
		{"kprobe", "security_path_unlink", []FimFunc{{"security_path_unlink(const struct path*, struct dentry*)", "bpf_file.o"}}},
		{"kprobe", "do_dentry_open", []FimFunc{{"do_dentry_open(struct file*, struct inode*, int (*p)(struct inode*, struct file*))", "bpf_file.o"}}},
		{"kprobe", "vfs_rmdir", []FimFunc{
			{"vfs_rmdir(struct inode*, struct dentry*)", "bpf_file.o"},
			{"vfs_rmdir(struct user_namespace*, struct inode*, struct dentry*)", "bpf_file_v512.o"},
		}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_file.o"},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_file_v512.o"},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_file.o"},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_file.o"},
		}},
	}

	SharedMaps = [...]string{
		"mkdir_retprobe_map",
		"lpm_trie_map_alloc",
		"hash_map_file_alloc",
		"hash_map_dir_alloc",
	}
)

type observerFileSensor struct {
	name string
}

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterTracingSensorsAtInit(file.name, file)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE, handleFileOps)
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

func getDevMajor(dev uint64) uint32 {
	sDev := int64(dev)
	return uint32(((sDev >> 8) & 0xfff) | ((sDev >> 32) & ^0xfff))
}

func getDevMinor(dev uint64) uint32 {
	sDev := int64(dev)
	return uint32((sDev & 0xff) | ((sDev >> 12) & ^0xff))
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

func addFilePath(handle *ebpf.Map, key fileapi.HashMapFileKey, val fileapi.HashMapFileVal) error {
	err := handle.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func IsSymlink(m fs.FileMode) bool {
	return m&fs.ModeSymlink != 0
}

func IsBlockDevice(m fs.FileMode) bool {
	return m&fs.ModeDevice != 0
}

func IsNamedPipe(m fs.FileMode) bool {
	return m&fs.ModeNamedPipe != 0
}

func IsSocket(m fs.FileMode) bool {
	return m&fs.ModeSocket != 0
}

func IsCharDevice(m fs.FileMode) bool {
	return m&fs.ModeCharDevice != 0
}

func CheckFileMode(mode fs.FileMode, path string) {
	l := logger.GetLogger()
	if IsBlockDevice(mode) {
		l.Infof("Ignoring block device %s", path)
	} else if IsNamedPipe(mode) {
		l.Infof("Ignoring named pipe %s", path)
	} else if IsSocket(mode) {
		l.Infof("Ignoring socket %s", path)
	} else if IsCharDevice(mode) {
		l.Infof("Ignoring character device %s", path)
	} else if IsSymlink(mode) {
		l.Infof("Ignoring symbolic link %s", path)
	} else {
		l.Warnf("Unknown file type %s -> %d", path, mode)
	}
}

func WalkPath(path string, fileHandle *ebpf.Map, dirHandle *ebpf.Map, lpmHandle *ebpf.Map, action uint32) {
	l := logger.GetLogger()
	totalFiles := 0
	totalDirectories := 0

	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			l.Infof("%s", err.Error())
			return nil
		}

		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() && !IsSymlink(mode) {
			CheckFileMode(mode, path)
			return nil
		}

		if IsSymlink(mode) {
			link, err := filepath.EvalSymlinks(path)
			if err != nil {
				l.Infof("Cannot resolve symlink %s", path)
				return nil
			}
			path = link
		}

		fileinfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		stat, ok := fileinfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat is not a syscall.Stat_t")
		}

		switch mode := fileinfo.Mode(); {
		case mode.IsRegular():
			key := fileapi.HashMapFileKey{
				Ino:      stat.Ino,
				DevMajor: getDevMajor(stat.Dev),
				DevMinor: getDevMinor(stat.Dev),
			}

			var val fileapi.HashMapFileVal

			val.Action = action
			val.PathSize = uint32(len(path))
			copy(val.FullPath[:], path)

			err := addFilePath(fileHandle, key, val)
			if err != nil {
				return fmt.Errorf("failed to call addFilePath: %w", err)
			}

			totalFiles++
		case mode.IsDir():
			key := fileapi.HashMapFileKey{
				Ino:      stat.Ino,
				DevMajor: getDevMajor(stat.Dev),
				DevMinor: getDevMinor(stat.Dev),
			}

			var val fileapi.HashMapFileVal

			// We should have all directory names to end with "/"
			// Check if this is the case, otherwise add it.
			if path[len(path)-1:] != "/" {
				path += "/"
			}

			val.Action = action
			val.PathSize = uint32(len(path))
			copy(val.FullPath[:], path)

			err := addFilePath(dirHandle, key, val)
			if err != nil {
				return fmt.Errorf("failed to call addDirPath: %w", err)
			}

			totalDirectories++
		case IsSymlink(mode):
			l.Warnf("%s is still a symlink\n", path)
		default:
			CheckFileMode(mode, path)
		}

		return nil
	})

	l.Infof("Added %d file(s) and %d directorie(s)\n", totalFiles, totalDirectories)
}

func addFileMonitoringSensor(kprobes v1alpha1.FileSpec, btfBaseFile string, fimProgs []FimProg) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map
	var err error

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
		Pinning:    ebpf.PinByName,
	}

	mo := ebpf.MapOptions{
		PinPath:        mapDir,
		LoadPinOptions: ebpf.LoadPinOptions{},
	}

	lpmMap, err = ebpf.NewMapWithOptions(ms, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	hs := &ebpf.MapSpec{
		Name:       "hash_map_file_alloc",
		Type:       bpf.BPF_MAP_TYPE_HASH,
		KeySize:    uint32(unsafe.Sizeof(fileapi.HashMapFileKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.HashMapFileVal{})),
		MaxEntries: maxWatchedFiles,
		Flags:      0,
		Pinning:    ebpf.PinByName,
	}

	fileMap, err = ebpf.NewMapWithOptions(hs, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	ds := &ebpf.MapSpec{
		Name:       "hash_map_dir_alloc",
		Type:       bpf.BPF_MAP_TYPE_HASH,
		KeySize:    uint32(unsafe.Sizeof(fileapi.HashMapFileKey{})),
		ValueSize:  uint32(unsafe.Sizeof(fileapi.HashMapFileVal{})),
		MaxEntries: maxWatchedDirs,
		Flags:      0,
		Pinning:    ebpf.PinByName,
	}

	dirMap, err = ebpf.NewMapWithOptions(ds, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	for _, str := range kprobes.Paths {
		l.Infof("WatchPath = %s", str)
		err := addFilter(lpmMap, str, filterMatch)
		if err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
		WalkPath(str, fileMap, dirMap, lpmMap, filterMatch)
	}

	for _, str := range kprobes.PathsExclude {
		l.Infof("ExcludePaths = %s", str)
		err := addFilter(lpmMap, str, filterIgnore)
		if err != nil {
			return nil, fmt.Errorf("failed to add ExcludePath: %w", err)
		}
		WalkPath(str, fileMap, dirMap, lpmMap, filterIgnore)
	}

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.name),
			fmt.Sprintf("%s_%s", h.tp, h.name),
			"kprobe")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		progs = append(progs, load)

		for _, m := range SharedMaps {
			maps = append(
				maps,
				program.MapBuilder(m, load),
			)
		}
	}

	return &sensors.Sensor{
		Name:  "file_monitoring_sensor",
		Progs: progs,
		Maps:  maps,
	}, nil
}

func findHooks() ([]FimProg, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("LoadKernelSpec %w", err)
	}

	fimProgs := make([]FimProg, 0)
	for _, h := range FimHooks {
		kretprobe := (h.tp == "kretprobe")
		p := fgsBTF.GetFuncProto(spec, h.name, kretprobe)

		progFound := false
		for _, f := range h.prog {
			if f.proto == p {
				progFound = true
				fimProgs = append(fimProgs, FimProg{h.tp, h.name, f.progName})
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
		return nil, fmt.Errorf("FileMonitoring requires more that one file_paths when file_paths_exclude is defined")
	}
	if len(spec.FileMonitoring.Paths) > 0 {
		if !kernels.MinKernelVersion("5.4.0") {
			return nil, fmt.Errorf("FileMonitoring requires at least 5.4.0 version")
		}
		logger.GetLogger().Infof("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))
		progs, err := findHooks()
		if err != nil {
			return nil, err
		}
		return addFileMonitoringSensor(spec.FileMonitoring, option.Config.BTF, progs)
	}
	return nil, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k *observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	// all is done in SpecHandler
	return nil
}
