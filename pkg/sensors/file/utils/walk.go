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
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

type InodeStore interface {
	LookupFilter(string) fileapi.LPMMapValue
	AddInode(fileapi.InodeKey, fileapi.InodeVal) error
	RemoveInode(fileapi.InodeKey) error
	LookupInode(fileapi.InodeKey, *fileapi.InodeVal) error
}

type FimMaps struct {
	Inode *ebpf.Map
	Lpm   *ebpf.Map
}

func OpenFIMMaps(mapDir string, pinPath string) (FimMaps, func(), error) {
	var inodeHandle, lpmHandle *ebpf.Map
	var err error

	inodeHandle, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, sensors.PathJoin(pinPath, InodeMapName)), nil)
	if err != nil {
		return FimMaps{}, func() {}, err
	}

	lpmHandle, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, sensors.PathJoin(pinPath, LpmMapName)), nil)
	if err != nil {
		inodeHandle.Close()
		return FimMaps{}, func() {}, err
	}

	cleanupFn := func() {
		inodeHandle.Close()
		lpmHandle.Close()
	}

	maps := FimMaps{
		Inode: inodeHandle,
		Lpm:   lpmHandle,
	}

	return maps, cleanupFn, nil
}

func (m FimMaps) LookupFilter(filter string) fileapi.LPMMapValue {
	var k fileapi.LPMMapKey
	var v fileapi.LPMMapValue

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	err := m.Lpm.Lookup(k, &v)
	if err != nil { // key does not exist so ignore
		return fileapi.LPMMapValue{Action: FilterIgnore}
	}
	return v
}

func (m FimMaps) AddInode(key fileapi.InodeKey, val fileapi.InodeVal) error {
	err := m.Inode.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func (m FimMaps) RemoveInode(key fileapi.InodeKey) error {
	err := m.Inode.Delete(key)
	if err != nil {
		return fmt.Errorf("failed handle.Delete: %w", err)
	}
	return nil
}

func (m FimMaps) LookupInode(key fileapi.InodeKey, valOut *fileapi.InodeVal) error {
	err := m.Inode.Lookup(key, valOut)
	if err != nil {
		return fmt.Errorf("failed handle.Lookup: %w", err)
	}
	return nil
}

type FimHashMap struct {
	M map[fileapi.InodeKey]fileapi.InodeVal
}

func InitFimHashMap(m map[fileapi.InodeKey]fileapi.InodeVal) FimHashMap {
	return FimHashMap{M: m}
}

func (m FimHashMap) LookupFilter(_ string) fileapi.LPMMapValue {
	return fileapi.LPMMapValue{Action: FilterIgnore}
}

func (m FimHashMap) AddInode(key fileapi.InodeKey, val fileapi.InodeVal) error {
	m.M[key] = val
	return nil
}

func (m FimHashMap) RemoveInode(key fileapi.InodeKey) error {
	delete(m.M, key)
	return nil
}

func (m FimHashMap) LookupInode(key fileapi.InodeKey, valOut *fileapi.InodeVal) error {
	*valOut = m.M[key]
	return nil
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
		l.Debugf("Ignoring block device %s", path)
	} else if IsNamedPipe(mode) {
		l.Debugf("Ignoring named pipe %s", path)
	} else if IsSocket(mode) {
		l.Debugf("Ignoring socket %s", path)
	} else if IsCharDevice(mode) {
		l.Debugf("Ignoring character device %s", path)
	} else if IsSymlink(mode) {
		l.Debugf("Ignoring symbolic link %s", path)
	} else {
		l.Warnf("Unknown file type %s -> %d", path, mode)
	}
}

func rmHandleContainerEntries(handle *ebpf.Map, containerID string) (int, error) {
	var key fileapi.InodeKey
	var val fileapi.InodeVal

	count := 0
	for {
		entries := handle.Iterate()
		keyFound := false
		for entries.Next(&key, &val) {
			if val.LocationFlags == fileapi.CONTAINER_FILE && string(val.ContainerID[:]) == containerID {
				if err := handle.Delete(key); err == nil {
					count++
				}
				keyFound = true
				break
			}
		}

		// We iterate the whole map and no keys found for the specified containerID.
		// We can stop searching now.
		if !keyFound {
			break
		}
	}

	return count, nil
}

// similar to rmHandleContainerEntries but uses BatchDelete and thus it is more efficient
// only supported in kernels >= 5.6
func rmHandleContainerEntries56(handle *ebpf.Map, containerID string) (int, error) {
	var key fileapi.InodeKey
	var val fileapi.InodeVal
	var keys []fileapi.InodeKey

	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		if val.LocationFlags == fileapi.CONTAINER_FILE && string(val.ContainerID[:]) == containerID {
			keys = append(keys, key)
		}
	}

	if err := entries.Err(); err != nil {
		return 0, err
	}

	count, err := handle.BatchDelete(keys, nil)
	if err != nil {
		return 0, err
	}

	if count != len(keys) {
		return 0, fmt.Errorf("BatchDelete: expected %d deletions got %d", len(keys), count)
	}

	return count, nil
}

func RemoveContainerEntries(handle *ebpf.Map, containerID string) error {
	rmEntries := rmHandleContainerEntries
	if kernels.MinKernelVersion("5.6.0") {
		rmEntries = rmHandleContainerEntries56
	}

	num, err := rmEntries(handle, containerID)
	if num != 0 {
		logger.GetLogger().Warnf("Deleted %d inodes for container %s", num, containerID)
	}
	return err
}

// This function gets a prefix and returns all paths that match this prefix.
// For example let's say that both /etc/ (directory) and /etcfoo (file) exists.
// The user provides /etc, which means that we care for everything that have
// this prefix. This function will return an array of /etc and /etcfoo that
// will be used by filepath.Walk() to be walked.
func GetPrefixMatch(path string) ([]string, error) {
	// we only accept absolute paths
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("only absolute paths are supported: [%s]", path)
	}

	// User provided a path that ends with "/" (i.e. /etc/)
	// This means that we care only for everything inside /etc/.
	// Nothing more to do here.
	if strings.HasSuffix(path, "/") {
		return []string{path}, nil
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	pattern := fmt.Sprintf("%s*", base)

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, file := range files {
		match, err := filepath.Match(pattern, file.Name())
		if err != nil {
			return nil, err
		}
		if match {
			result = append(result, filepath.Join(dir, file.Name()))
		}
	}
	return result, nil
}

type PathMatcher interface {
	GetWalkPath() string
	OverrideAction(uint32, fs.FileMode) uint32
	MatchPath(string, fs.FileMode) bool
	String() string
}

type PrefixPathMatcher struct {
	WalkPath string
	Prefix   string
}

func (p PrefixPathMatcher) GetWalkPath() string {
	if p.WalkPath != "" {
		return p.WalkPath
	}
	return p.Prefix
}

func (p PrefixPathMatcher) OverrideAction(action uint32, _ fs.FileMode) uint32 {
	return action
}

func (p PrefixPathMatcher) MatchPath(_ string, _ fs.FileMode) bool {
	return true
}
func (p PrefixPathMatcher) String() string {
	return fmt.Sprintf("prefix:[%s]", p.Prefix)
}

type PrefixSuffixFileMatcher struct {
	WalkPath string
	Prefix   string
	Suffix   string
}

func (p PrefixSuffixFileMatcher) GetWalkPath() string {
	if p.WalkPath != "" {
		return p.WalkPath
	}
	return p.Prefix
}

func (p PrefixSuffixFileMatcher) OverrideAction(action uint32, mode fs.FileMode) uint32 {
	if mode.IsDir() {
		return FilterMonitor
	}
	return action
}

func (p PrefixSuffixFileMatcher) MatchPath(path string, mode fs.FileMode) bool {
	if mode.IsDir() {
		return true
	}
	if !mode.IsRegular() {
		return false
	}
	// do not match on overlapping prefix and suffix
	if len(path) < len(p.Prefix)+len(p.Suffix) {
		return false
	}
	return strings.HasPrefix(path, p.Prefix) && strings.HasSuffix(path, p.Suffix)
}

func (p PrefixSuffixFileMatcher) String() string {
	return fmt.Sprintf("prefix:[%s], file_suffix:[%s]", p.Prefix, p.Suffix)
}

type ExactPathFileMatcher struct {
	WalkPath string
	Path     string
}

func (p ExactPathFileMatcher) GetWalkPath() string {
	if p.WalkPath != "" {
		return p.WalkPath
	}
	return p.Path
}

func (p ExactPathFileMatcher) OverrideAction(action uint32, mode fs.FileMode) uint32 {
	if mode.IsDir() {
		return FilterMonitor
	}
	return action
}

func (p ExactPathFileMatcher) MatchPath(path string, mode fs.FileMode) bool {
	if mode.IsDir() {
		return true
	}
	if !mode.IsRegular() {
		return false
	}
	return path == p.Path
}

func (p ExactPathFileMatcher) String() string {
	return fmt.Sprintf("exact:[%s]", p.Path)
}

func WalkPathRaw(matcher PathMatcher, rule uint32, store InodeStore, op uint32, action uint32, checkPrefix bool, locationFn func(v *fileapi.InodeVal)) (int, int, error) {
	l := logger.GetLogger()
	totalFiles := 0
	totalDirectories := 0
	removedDirectory := false

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			l.Debugf("%s", err.Error())
			return nil
		}

		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() && !IsSymlink(mode) && !IsBlockDevice(mode) && !IsCharDevice(mode) {
			CheckFileMode(mode, path)
			return nil
		}

		if IsSymlink(mode) {
			link, err := filepath.EvalSymlinks(path)
			if err != nil {
				l.WithError(err).Debugf("Cannot resolve symlink %s", link)
				return nil
			}
			path = link
		}

		fileinfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		if !matcher.MatchPath(path, fileinfo.Mode()) {
			return nil
		}

		action := matcher.OverrideAction(action, fileinfo.Mode())

		stat, ok := fileinfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat is not a syscall.Stat_t")
		}

		switch mode := fileinfo.Mode(); {
		case mode.IsRegular(), IsBlockDevice(mode.Type()), IsCharDevice(mode.Type()):
			key := fileapi.InodeKey{
				Ino:      stat.Ino,
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
			}

			if op == AddToMap {
				var val fileapi.InodeVal

				val.Action = action
				val.PathSize = uint32(len(path))
				copy(val.FullPath[:], path)
				locationFn(&val)
				val.RuleID = rule
				val.Mode = fileapi.HashMapFileModeFile

				addToMap := true
				if checkPrefix {
					if store.LookupFilter(path).Action == FilterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := store.AddInode(key, val)
					if err != nil {
						return fmt.Errorf("failed to call addFilePath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := store.RemoveInode(key)
				if err != nil && checkPrefix {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
			}

			totalFiles++
		case mode.IsDir():
			key := fileapi.InodeKey{
				Ino:      stat.Ino,
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
			}

			if op == AddToMap {
				var val fileapi.InodeVal

				// We should have all directory names to end with "/"
				// Check if this is the case, otherwise add it.
				if path[len(path)-1:] != "/" {
					path += "/"
				}

				val.Action = action
				val.PathSize = uint32(len(path))
				copy(val.FullPath[:], path)
				locationFn(&val)
				val.RuleID = rule
				val.Mode = fileapi.HashMapFileModeDirectory

				addToMap := true
				if checkPrefix {
					if store.LookupFilter(path).Action == FilterIgnore {
						addToMap = false
					}
				}
				if addToMap {
					err := store.AddInode(key, val)
					if err != nil {
						return fmt.Errorf("failed to call addDirPath: %w", err)
					}
				}
			} else if op == RemoveFromMap {
				err := store.RemoveInode(key)
				if err != nil && checkPrefix {
					return fmt.Errorf("failed to call removeFilePath: %w", err)
				}
				removedDirectory = removedDirectory || (err == nil)
			}

			totalDirectories++
		case IsSymlink(mode):
			l.Warnf("%s is still a symlink\n", path)
		default:
			CheckFileMode(mode, path)
		}

		return nil
	}

	path := matcher.GetWalkPath()
	paths, err := GetPrefixMatch(path)
	if err != nil {
		return 0, 0, err
	}

	for _, p := range paths {
		if err := filepath.Walk(p, walkFn); err != nil {
			return 0, 0, err
		}
	}

	// In the case of file_paths_exclude the previous loop removes all
	// entries that have been already added due to file_paths in a previous
	// call of this function. The following adds an entry for the top-level
	// directory with the FilterIgnore flag to avoid having new objects
	// created there to be monitored.
	// Checks:
	// 1. !checkPrefix -> not a rename operation
	// 2. removedDirectory -> if we did not removeany dirs in the previous step, the user excludes something that we didn't monitor
	if op == RemoveFromMap && action == FilterIgnore && !checkPrefix && removedDirectory {
		for _, p := range paths {
			info, err := os.Stat(p)
			if err != nil {
				continue
			}

			if !info.Mode().IsDir() {
				continue
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}

			key := fileapi.InodeKey{
				Ino:      stat.Ino,
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
			}

			if path[len(path)-1:] != "/" {
				path += "/"
			}

			val := fileapi.InodeVal{
				Action:   FilterIgnore,
				PathSize: uint32(len(path)),
				Mode:     fileapi.HashMapFileModeDirectory,
			}
			copy(val.FullPath[:], path)
			locationFn(&val)

			store.AddInode(key, val)
		}
	}

	// we are doing a rename operation so no need to follow all
	// path components
	if checkPrefix {
		return totalFiles, totalDirectories, nil
	}

	// Once walk is done successfully, we should add other path components
	// as well. As an example the user wants to monitor /dir/home/.
	// filepath.Walk will add directories and files inside  /dir/home/.
	// The next for loop will also add /dir/home/ and /dir/.
	// This is need in the case where the user removes /dir/home/
	// and creates that again.
	for {
		if path == "/" { // reached the root fs - nothing more to do
			break
		}

		// remove the rightmost path component
		path, _ = filepath.Split(strings.TrimSuffix(path, "/"))

		flInfo, statErr := os.Lstat(path)
		if statErr != nil {
			l.Debugf("%s", statErr.Error())
			return 0, 0, statErr
		}

		if mode := flInfo.Mode(); !mode.IsDir() {
			break
		}

		stat, ok := flInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("stat is not a syscall.Stat_t")
		}

		key := fileapi.InodeKey{
			Ino:      stat.Ino,
			DevMajor: GetDevMajor(stat.Dev),
			DevMinor: GetDevMinor(stat.Dev),
		}

		// We should have all directory names to end with "/"
		// Check if this is the case, otherwise add it.
		if path[len(path)-1:] != "/" {
			path += "/"
		}

		val := fileapi.InodeVal{
			Action:   FilterMonitor,
			PathSize: uint32(len(path)),
			Mode:     fileapi.HashMapFileModeDirectory,
		}
		copy(val.FullPath[:], path)
		locationFn(&val)

		var exVal fileapi.InodeVal
		if err := store.LookupInode(key, &exVal); err == nil { // key already exists
			// already exists with value FilterMatch, do not update to FilterIgnore.
			if exVal.Action == FilterMatch {
				continue
			}
		}

		if err := store.AddInode(key, val); err != nil {
			return 0, 0, fmt.Errorf("failed to call addDirPath: %w", err)
		}

		totalDirectories++
	}

	return totalFiles, totalDirectories, nil
}

func PathPatternToString(p v1alpha1.FilePathPattern) string {
	if p.Type == "FilePrefixSuffix" {
		return fmt.Sprintf("FilePrefixSuffix{Prefix:[%s],Suffix:[%s]}", p.FilePrefixSuffix.Prefix, p.FilePrefixSuffix.Suffix)
	} else if p.Type == "PathPrefix" {
		return fmt.Sprintf("PathPrefix{Prefix:[%s]}", p.PathPrefix.Prefix)
	} else if p.Type == "FileExactMatch" {
		return fmt.Sprintf("FileExactMatch{Path:[%s]}", p.FileExactMatch.Path)
	}
	return fmt.Sprintf("<unknown type: %s>", p.Type)
}

func GetMatcher(p v1alpha1.FilePathPattern, walkPath string) (PathMatcher, error) {
	switch p.Type {
	case "FilePrefixSuffix":
		return PrefixSuffixFileMatcher{
			WalkPath: walkPath,
			Prefix:   p.FilePrefixSuffix.Prefix,
			Suffix:   p.FilePrefixSuffix.Suffix,
		}, nil
	case "PathPrefix":
		return PrefixPathMatcher{
			WalkPath: walkPath,
			Prefix:   p.PathPrefix.Prefix,
		}, nil
	case "FileExactMatch":
		return ExactPathFileMatcher{
			WalkPath: walkPath,
			Path:     p.FileExactMatch.Path,
		}, nil
	default:
		return nil, fmt.Errorf("unknown type (%s) in PathsPatterns", p.Type)
	}
}

// CheckPath checks if the path should be monitored or ignored based on the
// file spec. It returns the action to be taken and the ruleID that matched.
func CheckPath(spec v1alpha1.FileSpec, path string, mode fs.FileMode) (uint32, uint32, error) {
	// if this is a directory add a trailing slash
	if mode.IsDir() {
		if path[len(path)-1] != '/' {
			path += "/"
		}
	}

	// by default we ignore the path
	ret := uint32(FilterIgnore)
	ruleID := uint32(0)
	for i, p := range spec.PathsPatterns {
		matcher, err := GetMatcher(p, "")
		if err != nil {
			return 0, 0, err
		}

		if !matcher.MatchPath(path, mode) {
			continue
		}

		a := matcher.OverrideAction(uint32(FilterMatch), mode)
		if a == FilterMatch || a == FilterMonitor {
			ret = a
			ruleID = uint32(i)
		}

		// we matched so no need to check more rules
		if ret == FilterMatch {
			break
		}
	}

	// nothing matched, so no need to check exclude
	if ret == FilterIgnore {
		return ret, ruleID, nil
	}

	// now check if this path should be excluded
	for _, e := range spec.PathsExclude {
		if strings.HasPrefix(path, e) {
			return FilterIgnore, 0, nil
		}
	}

	return ret, ruleID, nil
}

// This function is used to walk the path and remove inodes from the map.
func WalkPathRenameCleanup(path string, store InodeStore) error {
	return filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat is not a syscall.Stat_t")
		}

		switch mode := info.Mode(); {
		case mode.IsRegular(), mode.IsDir(), IsBlockDevice(mode.Type()), IsCharDevice(mode.Type()):
			store.RemoveInode(fileapi.InodeKey{
				Ino:      stat.Ino,
				DevMajor: GetDevMajor(stat.Dev),
				DevMinor: GetDevMinor(stat.Dev),
			})
		}

		return nil
	})
}

// This function is used to walk the path and add inodes to the map.
// It is used in the case of a rename operation when we move a directory
// inside or internally a watched directory.
func WalkPathRenameAdd(path string, store InodeStore, actionFn func(string, fs.FileMode) (uint32, uint32, error), locationFn func(v *fileapi.InodeVal)) error {
	return filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if IsSymlink(info.Mode()) {
			link, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil
			}
			path = link
		}

		fileinfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		action, ruleID, err := actionFn(path, fileinfo.Mode())
		if err != nil {
			return err
		}

		if action == FilterIgnore {
			return nil
		}

		stat, ok := fileinfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat is not a syscall.Stat_t")
		}

		key := fileapi.InodeKey{
			Ino:      stat.Ino,
			DevMajor: GetDevMajor(stat.Dev),
			DevMinor: GetDevMinor(stat.Dev),
		}

		val := fileapi.InodeVal{
			Action:   action,
			PathSize: uint32(len(path)),
			RuleID:   ruleID,
		}
		locationFn(&val)

		switch mode := fileinfo.Mode(); {
		case mode.IsRegular(), mode.IsDir(), IsBlockDevice(mode.Type()), IsCharDevice(mode.Type()):
			if mode.IsDir() {
				// We should have all directory names to end with "/"
				// Check if this is the case, otherwise add it.
				if path[len(path)-1] != '/' {
					path += "/"
				}

				val.Mode = fileapi.HashMapFileModeDirectory
			} else {
				val.Mode = fileapi.HashMapFileModeFile
			}

			copy(val.FullPath[:], path)

			if err := store.AddInode(key, val); err != nil {
				return fmt.Errorf("failed to call AddInode: %w", err)
			}
		}

		return nil
	})
}
