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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

type FimMaps struct {
	File, Dir, Lpm *ebpf.Map
}

func OpenFIMMaps(mapDir string, pinPath string) (FimMaps, func(), error) {
	var fileHandle, dirHandle, lpmHandle *ebpf.Map
	var err error

	fileHandle, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, sensors.PathJoin(pinPath, FileMapName)), nil)
	if err != nil {
		return FimMaps{}, func() {}, err
	}

	dirHandle, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, sensors.PathJoin(pinPath, DirMapName)), nil)
	if err != nil {
		fileHandle.Close()
		return FimMaps{}, func() {}, err
	}

	lpmHandle, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, sensors.PathJoin(pinPath, LpmMapName)), nil)
	if err != nil {
		fileHandle.Close()
		dirHandle.Close()
		return FimMaps{}, func() {}, err
	}

	cleanupFn := func() {
		fileHandle.Close()
		dirHandle.Close()
		lpmHandle.Close()
	}

	maps := FimMaps{
		File: fileHandle,
		Dir:  dirHandle,
		Lpm:  lpmHandle,
	}

	return maps, cleanupFn, nil
}

func GetDevMajor(dev uint64) uint32 {
	sDev := int64(dev)
	return uint32(((sDev >> 8) & 0xfff) | ((sDev >> 32) & ^0xfff))
}

func GetDevMinor(dev uint64) uint32 {
	sDev := int64(dev)
	return uint32((sDev & 0xff) | ((sDev >> 12) & ^0xff))
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

func lookupFilter(handle *ebpf.Map, filter string) fileapi.LPMMapValue {
	var k fileapi.LPMMapKey
	var v fileapi.LPMMapValue

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	err := handle.Lookup(k, &v)
	if err != nil { // key does not exist so ignore
		return FilterIgnore
	}
	return v
}

func AddFilePath(handle *ebpf.Map, key fileapi.HashMapFileKey, val fileapi.HashMapFileVal) error {
	err := handle.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func RemoveFilePath(handle *ebpf.Map, key fileapi.HashMapFileKey) error {
	err := handle.Delete(key)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func WalkPathRaw(path string, maps FimMaps, op uint32, action uint32, checkPrefix bool) (int, int, error) {
	l := logger.GetLogger()
	totalFiles := 0
	totalDirectories := 0

	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
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
				l.WithError(err).Infof("Cannot resolve symlink %s", link)
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
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
			}

			if op == AddToMap {
				var val fileapi.HashMapFileVal

				val.Action = action
				val.PathSize = uint32(len(path))
				copy(val.FullPath[:], path)

				addToMap := true
				if checkPrefix {
					if lookupFilter(maps.Lpm, path) == FilterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := AddFilePath(maps.File, key, val)
					if err != nil {
						return fmt.Errorf("failed to call addFilePath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := RemoveFilePath(maps.File, key)
				if err != nil {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
			}

			totalFiles++
		case mode.IsDir():
			key := fileapi.HashMapFileKey{
				Ino:      stat.Ino,
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
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
					if lookupFilter(maps.Lpm, path) == FilterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := AddFilePath(maps.Dir, key, val)
					if err != nil {
						return fmt.Errorf("failed to call addDirPath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := RemoveFilePath(maps.Dir, key)
				if err != nil {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
			}

			totalDirectories++
		case IsSymlink(mode):
			l.Warnf("%s is still a symlink\n", path)
		default:
			CheckFileMode(mode, path)
		}

		return nil
	})

	if err == nil {
		return totalFiles, totalDirectories, nil
	}
	return 0, 0, err
}
