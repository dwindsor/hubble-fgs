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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
