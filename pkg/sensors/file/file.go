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
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

	"github.com/google/uuid"
)

const (
	filterIgnore = 0
	filterMatch  = 1

	AddToMap      = 0
	RemoveFromMap = 1

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

const (
	dirMapName  = "hash_map_dir_alloc"
	fileMapName = "hash_map_file_alloc"
	lpmMapName  = "lpm_trie_map_alloc"
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
			op = AddToMap
			action = filterMatch
		} else if hasFlag(m.Flags, MOVE_OUTSIDE) {
			op = RemoveFromMap
			action = filterIgnore
		}

		if option.Config.EnableK8s {
			ExecWalkPath(path, option.Config.MapDir, op, action, true)
		} else {
			WalkPath(path, option.Config.MapDir, op, action, true)
		}
	}

	// The following should not be possible to happen. If we catch any of these we should handle them
	// (not difficult to implement)
	l := logger.GetLogger()
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
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY]\n")
			} else if hasFlag(m.Flags, MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY]\n")
			} else if hasFlag(m.Flags, MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY]\n")
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

func lookupFilter(handle *ebpf.Map, filter string) fileapi.LPMMapValue {
	var k fileapi.LPMMapKey
	var v fileapi.LPMMapValue

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	err := handle.Lookup(k, &v)
	if err != nil { // key does not exist so ignore
		return filterIgnore
	}
	return v
}

func addFilePath(handle *ebpf.Map, key fileapi.HashMapFileKey, val fileapi.HashMapFileVal) error {
	err := handle.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func removeFilePath(handle *ebpf.Map, key fileapi.HashMapFileKey) error {
	err := handle.Delete(key)
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

func ExecWalkPath(paths string, mapDir string, op uint32, action uint32, checkPrefix bool) {
	cmd := exec.Command("fs-scanner",
		"-paths", paths,
		"-mapDir", mapDir,
		"-walkOp", strconv.FormatUint(uint64(op), 10),
		"-filterAction", strconv.FormatUint(uint64(action), 10),
		"-checkPrefix", strconv.FormatBool(checkPrefix),
		"-hostMntNs", strconv.FormatUint(uint64(namespace.GetPidNsInode(1, "mnt")), 10),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			logger.GetLogger().Warnf("fs-scanner exit code is %d", exitError.ExitCode())
		} else {
			logger.GetLogger().Warnf("cmd.run: %v", err)
		}
	}
}

func WalkPath(path string, mapDir string, op uint32, action uint32, checkPrefix bool) {
	l := logger.GetLogger()
	totalFiles := 0
	totalDirectories := 0

	fileHandle, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, fileMapName), nil)
	if err != nil {
		return
	}
	defer fileHandle.Close()

	dirHandle, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, dirMapName), nil)
	if err != nil {
		return
	}
	defer dirHandle.Close()

	lpmHandle, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, lpmMapName), nil)
	if err != nil {
		return
	}
	defer fileHandle.Close()

	errWalk := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if option.Config.Debug || option.Config.Verbosity >= 2 {
				l.Infof("%s", err.Error())
			}
			return nil
		}

		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() && !IsSymlink(mode) {
			if option.Config.Debug || option.Config.Verbosity >= 2 {
				CheckFileMode(mode, path)
			}
			return nil
		}

		if IsSymlink(mode) {
			link, err := filepath.EvalSymlinks(path)
			if err != nil {
				if option.Config.Debug || option.Config.Verbosity >= 2 {
					l.WithError(err).Infof("Cannot resolve symlink %s", link)
				}
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

			if op == AddToMap {
				var val fileapi.HashMapFileVal

				val.Action = action
				val.PathSize = uint32(len(path))
				copy(val.FullPath[:], path)

				addToMap := true
				if checkPrefix {
					if lookupFilter(lpmHandle, path) == filterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := addFilePath(fileHandle, key, val)
					if err != nil {
						return fmt.Errorf("failed to call addFilePath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := removeFilePath(fileHandle, key)
				if err != nil {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
			}

			totalFiles++
		case mode.IsDir():
			key := fileapi.HashMapFileKey{
				Ino:      stat.Ino,
				DevMajor: getDevMajor(stat.Dev),
				DevMinor: getDevMinor(stat.Dev),
			}

			if op == AddToMap {
				var val fileapi.HashMapFileVal

				// We should habe all directory names to end with "/"
				// Check if this is the case, otherwise add it.
				if path[len(path)-1:] != "/" {
					path += "/"
				}

				val.Action = action
				val.PathSize = uint32(len(path))
				copy(val.FullPath[:], path)

				addToMap := true
				if checkPrefix {
					if lookupFilter(lpmHandle, path) == filterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := addFilePath(dirHandle, key, val)
					if err != nil {
						return fmt.Errorf("failed to call addDirPath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := removeFilePath(fileHandle, key)
				if err != nil {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
			}

			totalDirectories++
		case IsSymlink(mode):
			l.Warnf("%s is still a symlink\n", path)
		default:
			if option.Config.Debug || option.Config.Verbosity >= 2 {
				CheckFileMode(mode, path)
			}
		}

		return nil
	})

	if errWalk != nil {
		l.WithError(errWalk).Warnf("filepath.Walk")
	}
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

	lpmMap, err := ebpf.NewMapWithOptions(ms, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	for _, str := range kprobes.Paths {
		if err := addFilter(lpmMap, str, filterMatch); err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range kprobes.PathsExclude {
		if err := addFilter(lpmMap, str, filterIgnore); err != nil {
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
		Pinning:    ebpf.PinByName,
	}

	_, err = ebpf.NewMapWithOptions(hs, mo)
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

	_, err = ebpf.NewMapWithOptions(ds, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	if option.Config.EnableK8s {
		if len(kprobes.Paths) > 0 {
			l.Infof("WatchPaths:")
			for _, p := range kprobes.Paths {
				if strings.Contains(p, ":") {
					return nil, fmt.Errorf("watchPath %s cannot contain a ':'", p)
				}
			}
			ExecWalkPath(strings.Join(kprobes.Paths[:], ":"), option.Config.MapDir, AddToMap, filterMatch, false)
		}
		if len(kprobes.PathsExclude) > 0 {
			l.Infof("ExcludePaths:")
			for _, p := range kprobes.PathsExclude {
				if strings.Contains(p, ":") {
					return nil, fmt.Errorf("excludePath %s cannot include a ':'", p)
				}
			}
			ExecWalkPath(strings.Join(kprobes.PathsExclude[:], ":"), option.Config.MapDir, AddToMap, filterIgnore, false)
		}
	} else {
		for _, str := range kprobes.Paths {
			l.Infof("WatchPath = %s", str)
			WalkPath(str, option.Config.MapDir, AddToMap, filterMatch, false)
		}

		for _, str := range kprobes.PathsExclude {
			l.Infof("ExcludePaths = %s", str)
			WalkPath(str, option.Config.MapDir, AddToMap, filterIgnore, false)
		}
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
		if !kernels.MinKernelVersion("4.19.0") {
			logger.GetLogger().Warnf("FileMonitoring requires at least 4.19.0 version")
			return nil, nil
		}
		logger.GetLogger().Infof("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))
		progs, err := findHooks()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("FileMonitoring fails to find the appropriate hooks")
			return nil, nil
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
