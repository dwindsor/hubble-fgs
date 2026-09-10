// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux

// go test -gcflags="" -c ./pkg/sensors/file/utils -o go-tests/file-utils.test
// ./go-tests/file-utils.test -test.run TestWalk

package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

var (
	workingDir = "/tmp"
)

func createTestDir(t *testing.T, path string) {
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatalf("Mkdir failed: %s\n", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Fatalf("Remove testfile failed: %s\n", err)
		}
	})
}

func createTestFile(t *testing.T, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	t.Cleanup(func() {
		if err := os.RemoveAll(filename); err != nil {
			t.Fatalf("Remove testfile failed: %s\n", err)
		}
	})
}

func TestWalkRelative(t *testing.T) {
	_, err := GetPrefixMatch("./some_relative_path")
	assert.Error(t, err)
}

func TestWalkSingleDir(t *testing.T) {
	dirPath := filepath.Join(workingDir, fmt.Sprintf("walk_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, dirPath)

	paths, err := GetPrefixMatch(dirPath)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(paths))
	assert.Equal(t, dirPath, paths[0])
}

func TestWalkDirFile(t *testing.T) {
	dirPath := filepath.Join(workingDir, fmt.Sprintf("walk_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, dirPath)
	filePath := filepath.Join(workingDir, fmt.Sprintf("walk_test_file_%s", filepath.Base(t.Name())))
	createTestFile(t, filePath)

	paths, err := GetPrefixMatch(filepath.Join(workingDir, "walk_test"))
	assert.NoError(t, err)
	assert.Equal(t, 2, len(paths))
	if paths[0] == dirPath {
		assert.Equal(t, dirPath, paths[0])
		assert.Equal(t, filePath, paths[1])
	} else {
		assert.Equal(t, filePath, paths[0])
		assert.Equal(t, dirPath, paths[1])
	}
}

func TestWalkDirFileNoPrefix(t *testing.T) {
	dirPath := filepath.Join(workingDir, fmt.Sprintf("walk_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, dirPath)
	dirPathLong := filepath.Join(workingDir, fmt.Sprintf("walk_test_dir_%s_foo", filepath.Base(t.Name())))
	createTestDir(t, dirPathLong)

	dirPathSlash := fmt.Sprintf("%s/", dirPath)
	paths, err := GetPrefixMatch(dirPathSlash)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(paths))
	assert.Equal(t, dirPathSlash, paths[0])
}

func TestWalkSinglePrefixNotExist(t *testing.T) {
	paths, err := GetPrefixMatch("/SOME_RANDOM_PATH_THAT_DOES_NOT_EXIST")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(paths))
}

func TestWalkSingleDirNotExist(t *testing.T) {
	dirPath := "/SOME_RANDOM_PATH_THAT_DOES_NOT_EXIST/"
	paths, err := GetPrefixMatch(dirPath)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(paths))
	assert.Equal(t, dirPath, paths[0])
}

func inodeKeyForTest(t *testing.T, path string) fileapi.InodeKey {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %s", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat for %s is not a syscall.Stat_t", path)
	}

	return fileapi.InodeKey{
		Ino:      stat.Ino,
		DevMajor: GetDevMajor(stat.Dev),
		DevMinor: GetDevMinor(stat.Dev),
	}
}

// TestWalkPathRawDoesNotFollowSymlinks verifies that policy load walks cannot
// add an out-of-prefix symlink target to the inode map and exclude walks cannot
// remove that target from the map.
func TestWalkPathRawDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	watched := filepath.Join(root, "watched")
	if err := os.Mkdir(watched, 0755); err != nil {
		t.Fatalf("mkdir watched directory: %s", err)
	}

	regular := filepath.Join(watched, "regular")
	createTestFile(t, regular)
	victim := filepath.Join(root, "victim")
	createTestFile(t, victim)
	if err := os.Symlink(victim, filepath.Join(watched, "symlink")); err != nil {
		t.Fatalf("create symlink: %s", err)
	}

	regularKey := inodeKeyForTest(t, regular)
	victimKey := inodeKeyForTest(t, victim)
	matcher := PrefixPathMatcher{Prefix: watched + "/"}
	locationFn := func(_ *fileapi.InodeVal) {}

	assert.False(t, matcher.MatchPath(victim, 0, nil))

	t.Run("add", func(t *testing.T) {
		store := InitFimHashMap(make(map[fileapi.InodeKey]fileapi.InodeVal))
		err := WalkPathRaw(matcher, 0, store, AddToMap, FilterMatch, locationFn)
		assert.NoError(t, err)
		assert.Contains(t, store.M, regularKey)
		assert.NotContains(t, store.M, victimKey)
	})

	t.Run("remove", func(t *testing.T) {
		store := InitFimHashMap(map[fileapi.InodeKey]fileapi.InodeVal{
			victimKey: {},
		})
		err := WalkPathRaw(matcher, 0, store, RemoveFromMap, FilterIgnore, locationFn)
		assert.NoError(t, err)
		assert.Contains(t, store.M, victimKey)
	})
}

// TestWalkPathRenameAddDoesNotFollowSymlinks verifies that a directory moved
// into a watched tree cannot use a contained symlink to register an unrelated
// target inode.
func TestWalkPathRenameAddDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(moved, 0755); err != nil {
		t.Fatalf("mkdir moved directory: %s", err)
	}

	regular := filepath.Join(moved, "regular")
	createTestFile(t, regular)
	victim := filepath.Join(root, "victim")
	createTestFile(t, victim)
	if err := os.Symlink(victim, filepath.Join(moved, "symlink")); err != nil {
		t.Fatalf("create symlink: %s", err)
	}

	regularKey := inodeKeyForTest(t, regular)
	victimKey := inodeKeyForTest(t, victim)
	store := InitFimHashMap(make(map[fileapi.InodeKey]fileapi.InodeVal))
	actionFn := func(_ string, _ fs.FileMode) (uint32, uint32, error) {
		return FilterMatch, 0, nil
	}
	locationFn := func(_ *fileapi.InodeVal) {}

	_, err := WalkPathRenameAdd(moved, store, actionFn, locationFn)
	assert.NoError(t, err)
	assert.Contains(t, store.M, regularKey)
	assert.NotContains(t, store.M, victimKey)
}
