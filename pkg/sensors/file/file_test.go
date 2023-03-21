//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// go test -gcflags="" -c ./pkg/sensors/file -o go-tests/file.test
// sudo ./go-tests/file.test --bpf-lib ./bpf/objs/ [ -test.run TestCopyFileRange ]

package file

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	workingDir = "/tmp"
)

func TestMain(m *testing.M) {
	// cleanup all files that may exist from previous tests
	if workDirs, err := filepath.Glob(filepath.Join(workingDir, "fim_test_*")); err == nil {
		for _, f := range workDirs {
			os.RemoveAll(f)
		}
	}

	ec := runner.TestSensorsRun(m, "SensorFile")
	os.Exit(ec)
}

const (
	renameDelay = 200
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func TestStructAlignments(t *testing.T) {
	path := filepath.Join(runner.Conf().TetragonLib, "bpf_alignchecker.o")
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		"hash_map_file_key":   {reflect.TypeOf(fileapi.HashMapFileKey{})},
		"hash_map_file_val":   {reflect.TypeOf(fileapi.HashMapFileVal{})},
		"msg_file_path":       {reflect.TypeOf(fileapi.MsgFilePath{})},
		"msg_fs_info":         {reflect.TypeOf(fileapi.MsgFsInfo{})},
		"msg_file_ops":        {reflect.TypeOf(fileapi.MsgFileEvent{})},
		"msg_file_split_path": {reflect.TypeOf(fileapi.MsgFileSplitPath{})},
		"msg_rename_elem":     {reflect.TypeOf(fileapi.MsgRenameElem{})},
		"msg_file_rename_ops": {reflect.TypeOf(fileapi.MsgFileRenameEvent{})},
	}
	err := check.CheckStructAlignments(path, toCheck, true)
	if err != nil {
		t.Errorf("TestStructAlignments failed: %s\n", err)
	}
}

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

func createFileInDir(t *testing.T, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}

	_, err = file.WriteString("some random test data here")
	if err != nil {
		t.Fatal(err)
	}

	file.Close()
}

func fallocateFileInDir(t *testing.T, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}

	size := int64(16 * 1024) // 16KB
	_, err = file.Seek(size-1, 0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = file.Write([]byte{0})
	if err != nil {
		t.Fatal(err)
	}

	file.Close()
}

func createSpecFile(t *testing.T, test_path string) string {
	specData := map[string]string{
		"MatchedPath": test_path,
	}

	specFname, err := testutils.GetSpecFromTemplate("file_monitoring.yaml.tmpl", specData)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.Remove(specFname); err != nil {
			t.Log(err)
		}
	})

	return specFname
}

func getInodeInfo(t *testing.T, fileName string) (uint64, string) {
	fileinfo, err := os.Stat(fileName)
	if err != nil {
		t.Errorf("os.Stat %s\n", err)
		return 0, ""
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Not a syscall.Stat_t")
		return 0, ""
	}

	return stat.Ino, fmt.Sprintf("%d:%d", fm.GetDevMajor(stat.Dev), fm.GetDevMinor(stat.Dev))
}

func genericArgFilenameChecker(fileName string, ino uint64, dev string) *ec.FileArgumentChecker {
	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(fileName)).WithInode(i).WithLocation(l)
	c := ec.NewGenericFileArgChecker().WithFile(f)
	return ec.NewFileArgumentChecker().WithGenericArg(c)
}

func runReadWriteTest(gt *testing.T, t *testing.T, exec_path string, create_file bool, act tetragon.FileAction) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")
	if create_file == true {
		createFileInDir(t, test_file)
	}

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/" + exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	ino, dev := getInodeInfo(t, test_file)
	fileChecker := ec.NewProcessFileChecker("").
		WithAction(act).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func runCopyTest(gt *testing.T, t *testing.T, exec_path string) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(test_path, "test2")

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/" + exec_path)
	testCmd := exec.CommandContext(ctx, testBin, in_file, out_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	in_ino, in_dev := getInodeInfo(t, in_file)
	inFileChecker := ec.NewProcessFileChecker("inFile").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(in_file, in_ino, in_dev))
	out_ino, out_dev := getInodeInfo(t, out_file)
	outFileChecker := ec.NewProcessFileChecker("outFile").
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(out_file, out_ino, out_dev))
	checker := ec.NewUnorderedEventChecker(
		inFileChecker,
		outFileChecker,
	)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func runMmapTest(gt *testing.T, t *testing.T, exec_path string, act tetragon.FileAction) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")
	fallocateFileInDir(t, test_file)

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/" + exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	ino, dev := getInodeInfo(t, test_file)
	fileCheckerRead := ec.NewProcessFileChecker("readChecker").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	fileCheckerWrite := ec.NewProcessFileChecker("writeChecker").
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(
		fileCheckerRead,
		fileCheckerWrite,
	)
	if act == tetragon.FileAction_FILE_READ {
		checker = ec.NewUnorderedEventChecker(fileCheckerRead)
	}

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

// tests in "hubble-fgs/contrib/tester-progs/read_write"

func testFileRead(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/read", true, tetragon.FileAction_FILE_READ)
}

func testFileReadV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/readv", true, tetragon.FileAction_FILE_READ)
}

func testFilePReadV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/preadv", true, tetragon.FileAction_FILE_READ)
}

func testFilePReadV2(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/preadv2", true, tetragon.FileAction_FILE_READ)
}

func testFilePRead64(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/pread64", true, tetragon.FileAction_FILE_READ)
}

func testFileWrite(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/write", false, tetragon.FileAction_FILE_WRITE)
}

func testFileWriteV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/writev", false, tetragon.FileAction_FILE_WRITE)
}

func testFilePWriteV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/pwritev", false, tetragon.FileAction_FILE_WRITE)
}

func testFilePWriteV2(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/pwritev2", false, tetragon.FileAction_FILE_WRITE)
}

func testFilePWrite64(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/read_write/pwrite64", false, tetragon.FileAction_FILE_WRITE)
}

func testSendfile(gt *testing.T, t *testing.T) {
	runCopyTest(gt, t, "tester-progs/read_write/sendfile")
}

func testCopyFileRange(gt *testing.T, t *testing.T) {
	runCopyTest(gt, t, "tester-progs/read_write/copy_file_range")
}

// tests in hubble-fgs/contrib/tester-progs/aio

func testFileAioPRead(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/aio/aio_pread", true, tetragon.FileAction_FILE_READ)
}

func testFileAioPReadV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/aio/aio_preadv", true, tetragon.FileAction_FILE_READ)
}

func testFileAioPWrite(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/aio/aio_pwrite", false, tetragon.FileAction_FILE_WRITE)
}

func testFileAioPWriteV(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/aio/aio_pwritev", false, tetragon.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/open

func testFileFallocate(gt *testing.T, t *testing.T) {
	runReadWriteTest(gt, t, "tester-progs/open/fallocate", false, tetragon.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/splice

func testFileSplice(gt *testing.T, t *testing.T) {
	runCopyTest(gt, t, "tester-progs/splice/splice")
}

// tests in hubble-fgs/contrib/tester-progs/io_uring

func testFileCatIouring(gt *testing.T, t *testing.T) {
	// io_uring introduced in kernel 5.1: https://lwn.net/Articles/810414/
	if !kernels.MinKernelVersion("5.1.0") {
		t.Skip("File monitoring (io_uring) requires at least 5.1.0 version")
	}

	runReadWriteTest(gt, t, "tester-progs/io_uring/cat_liburing", true, tetragon.FileAction_FILE_READ)
}

func testFileWriteIouring(gt *testing.T, t *testing.T) {
	// io_uring introduced in kernel 5.1: https://lwn.net/Articles/810414/
	if !kernels.MinKernelVersion("5.1.0") {
		t.Skip("File monitoring (io_uring) requires at least 5.1.0 version")
	}

	runReadWriteTest(gt, t, "tester-progs/io_uring/write_liburing", false, tetragon.FileAction_FILE_WRITE)
}

func testFileCpIouring(gt *testing.T, t *testing.T) {
	// io_uring introduced in kernel 5.1: https://lwn.net/Articles/810414/
	if !kernels.MinKernelVersion("5.1.0") {
		t.Skip("File monitoring (io_uring) requires at least 5.1.0 version")
	}

	runCopyTest(gt, t, "tester-progs/io_uring/cp_liburing")
}

// tests in hubble-fgs/contrib/tester-progs/mmap

func testFileMmapReadPopulate(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_populate_read", tetragon.FileAction_FILE_READ)
}

func testFileMmapWritePopulate(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_populate_write", tetragon.FileAction_FILE_WRITE)
}

func testFileMmapRead(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_read", tetragon.FileAction_FILE_READ)
}

func testFileMmapReadWrite(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_read_write", tetragon.FileAction_FILE_WRITE)
}

func testFileMmapWrite(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_write", tetragon.FileAction_FILE_WRITE)
}

func testFileMmapWriteRead(gt *testing.T, t *testing.T) {
	runMmapTest(gt, t, "tester-progs/mmap/mmap_write_read", tetragon.FileAction_FILE_WRITE)
}

func testFileDelete(gt *testing.T, t *testing.T) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	// get inode before removing the file
	ino, dev := getInodeInfo(t, in_file)

	errOp := os.Remove(in_file)
	if errOp != nil {
		t.Errorf("os.Remove failed (%s)", errOp)
	}

	inFileChecker := ec.NewProcessFileChecker("inFileChecker").
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(in_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(inFileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func fileExists(t *testing.T, filePath string) bool {
	_, err := os.Stat(filePath)
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	t.Fatalf("%s", err)
	return false
}

func fileCreate(t *testing.T, dirName string) {
	filePath := [2]string{
		filepath.Join(dirName, "newfile1.txt"),
		filepath.Join(dirName, "newfile2.txt"),
	}

	// check if the files already exist
	for _, path := range filePath {
		if ex := fileExists(t, path); ex == true {
			t.Fatalf("%s already exists. Exiting...", path)
		}
	}

	// create newfile1.txt
	file1, err := os.Create(filePath[0])
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer file1.Close()

	// create newfile2.txt
	data := []byte("hello\n")
	err = os.WriteFile(filePath[1], data, 0644)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func fileCleanup(t *testing.T, dirName string) {
	filePath := [2]string{
		filepath.Join(dirName, "newfile1.txt"),
		filepath.Join(dirName, "newfile2.txt"),
	}

	// remove files
	for _, path := range filePath {
		err := os.Remove(path)
		if err != nil {
			t.Fatalf("%s", err)
		}
	}
}

func getFilePermsUidGui(t *testing.T, fileName string) (string, string, string) {
	fileStats, err := os.Stat(fileName)
	if err != nil {
		t.Fatalf("file does not exist: %v", err)
	}

	perms := fileStats.Mode().Perm()
	permStr := fmt.Sprintf("%v (%#o)", perms, perms)

	userStr := "<unknown>"
	uID := fileStats.Sys().(*syscall.Stat_t).Uid
	uname, err1 := user.LookupId(strconv.FormatUint(uint64(uID), 10))
	if err1 == nil {
		userStr = fmt.Sprintf("%d (%s)", uID, uname.Username)
	}

	groupStr := "<unknown>"
	gID := fileStats.Sys().(*syscall.Stat_t).Gid
	gname, err2 := user.LookupGroupId(strconv.FormatUint(uint64(gID), 10))
	if err2 == nil {
		groupStr = fmt.Sprintf("%d (%s)", gID, gname.Name)
	}

	return permStr, userStr, groupStr
}

func testFileCreate(gt *testing.T, t *testing.T) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	fp1 := filepath.Join(test_path, "newfile1.txt")
	fp2 := filepath.Join(test_path, "newfile2.txt")

	fileCreate(t, test_path)

	ino1, dev1 := getInodeInfo(t, fp1)
	ino2, dev2 := getInodeInfo(t, fp2)

	perm1, uid1, gid1 := getFilePermsUidGui(t, fp1)
	perm2, uid2, gid2 := getFilePermsUidGui(t, fp2)

	fileCleanup(t, test_path)

	file1CreateChecker := ec.NewProcessFileChecker("file1Create").
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1)).
		WithPermissions(sm.Full(perm1)).
		WithUid(sm.Full(uid1)).
		WithGid(sm.Full(gid1))
	file2CreateChecker := ec.NewProcessFileChecker("file2Create").
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2)).
		WithPermissions(sm.Full(perm2)).
		WithUid(sm.Full(uid2)).
		WithGid(sm.Full(gid2))
	file2WriteChecker := ec.NewProcessFileChecker("file2Write").
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	file1DeleteChecker := ec.NewProcessFileChecker("file1Delete").
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1))
	file2DeleteChecker := ec.NewProcessFileChecker("file2Delete").
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	checker := ec.NewUnorderedEventChecker(
		file1CreateChecker,
		file2CreateChecker,
		file2WriteChecker,
		file1DeleteChecker,
		file2DeleteChecker,
	)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func TestLoadFileSensor(t *testing.T) {
	if !kernels.MinKernelVersion("4.19.0") {
		t.Skip("File monitoring requires at least 4.19.0 version")
	}

	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	specFname := createSpecFile(t, test_path)

	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}
	t.Cleanup(func() {
		TerminateFsScanner()
		ClearFIMTracingPolicies()
	})

	verSuffix := "v419"
	if kernels.MinKernelVersion("5.12.0") {
		verSuffix = "v512"
	}

	sensorProgs := []tus.SensorProg{
		0:  tus.SensorProg{Name: "vfs_fallocate", Type: ebpf.Kprobe},
		1:  tus.SensorProg{Name: "filemap_fault", Type: ebpf.Kprobe},
		2:  tus.SensorProg{Name: "filemap_map_pages", Type: ebpf.Kprobe},
		3:  tus.SensorProg{Name: "filemap_page_mkwrite", Type: ebpf.Kprobe},
		4:  tus.SensorProg{Name: "rw_verify_area", Type: ebpf.Kprobe},
		5:  tus.SensorProg{Name: fmt.Sprintf("vfs_unlink_%s", verSuffix), Type: ebpf.Kprobe},
		6:  tus.SensorProg{Name: "finish_open", Type: ebpf.Kprobe},
		7:  tus.SensorProg{Name: fmt.Sprintf("vfs_rmdir_%s", verSuffix), Type: ebpf.Kprobe},
		8:  tus.SensorProg{Name: fmt.Sprintf("vfs_mkdir_%s", verSuffix), Type: ebpf.Kprobe},
		9:  tus.SensorProg{Name: "vfs_mkdir_exit", Type: ebpf.Kprobe},
		10: tus.SensorProg{Name: "security_path_rename", Type: ebpf.Kprobe},
		11: tus.SensorProg{Name: "security_path_rename_exit", Type: ebpf.Kprobe},
		12: tus.SensorProg{Name: fmt.Sprintf("vfs_rename_%s", verSuffix), Type: ebpf.Kprobe},
		13: tus.SensorProg{Name: "vfs_rename_exit", Type: ebpf.Kprobe},
		14: tus.SensorProg{Name: "vfs_open", Type: ebpf.Kprobe},
		15: tus.SensorProg{Name: "iterate_dir", Type: ebpf.Kprobe},
		16: tus.SensorProg{Name: fmt.Sprintf("do_truncate_%s", verSuffix), Type: ebpf.Kprobe},
	}

	sensorMaps := []tus.SensorMap{
		// all programs that generate events
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 9, 13, 14, 15, 16}},
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16}},

		// shared maps
		tus.SensorMap{Name: "lpm_trie_map_alloc", Progs: []uint{6, 8, 13, 14}},
		tus.SensorMap{Name: "hash_map_file_alloc", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 13, 14, 16}},
		tus.SensorMap{Name: "hash_map_dir_alloc", Progs: []uint{6, 7, 8, 9, 12, 13, 14, 15}},
		tus.SensorMap{Name: "mkdir_retprobe_map", Progs: []uint{8, 9}},
		tus.SensorMap{Name: "rename_retprobe_map", Progs: []uint{10, 11, 12, 13}},
		tus.SensorMap{Name: "file_names_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16}},

		// separate maps
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{6}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{8}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{13}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{14}},

		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{6}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{8}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{14}},

		tus.SensorMap{Name: "file_heap_map", Progs: []uint{0}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{1}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{2}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{3}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{4}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{5}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{6}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{7}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{9}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{14}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{15}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{16}},

		tus.SensorMap{Name: "vfs_rename_info_heap", Progs: []uint{10}},

		tus.SensorMap{Name: "file_rename_heap_map", Progs: []uint{13}},

		tus.SensorMap{Name: "file_val_map", Progs: []uint{6}},
		tus.SensorMap{Name: "file_val_map", Progs: []uint{9}},
		tus.SensorMap{Name: "file_val_map", Progs: []uint{13}},
		tus.SensorMap{Name: "file_val_map", Progs: []uint{14}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}

func fileRead(t *testing.T, f string) {
	file, err := os.Open(f)
	if err != nil {
		t.Errorf("os.Open failed (%s)", err)
	}
	defer file.Close()

	data := make([]byte, 8)
	_, err = file.Read(data)
	if err != nil {
		t.Errorf("os.Read failed (%s)", err)
	}
}

func fileRemove(t *testing.T, f string) {
	if err := os.Remove(f); err != nil {
		t.Errorf("os.Remove failed (%s)", err)
	}
}

func renameDeleteChecker(f string) *ec.ProcessFileChecker {
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d := ec.NewFileDetailsChecker().WithFilename(sm.Full(f)).WithLocation(l)
	g := ec.NewGenericFileArgChecker().WithFile(d)
	a := ec.NewFileArgumentChecker().WithGenericArg(g)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameDelete(%s)", f)).
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(a)
}

func renameReadChecker(f string) *ec.ProcessFileChecker {
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d := ec.NewFileDetailsChecker().WithFilename(sm.Full(f)).WithLocation(l)
	i := ec.NewFileIOChecker().WithOffset(sm.Full("0")).WithSize(sm.Full("8"))
	g := ec.NewGenericFileArgChecker().WithFile(d).WithIo(i)
	a := ec.NewFileArgumentChecker().WithGenericArg(g)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameRead(%s)", f)).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(a)
}

func renameRenameChecker(file_a, file_b, mv, src, dst string) *ec.ProcessFileChecker {
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d1 := ec.NewFileDetailsChecker().WithFilename(sm.Full(file_a)).WithLocation(l)
	d2 := ec.NewFileDetailsChecker().WithFilename(sm.Full(file_b)).WithLocation(l)
	fl := ec.NewStringListMatcher().
		WithOperator(lm.Ordered).
		WithValues(
			sm.Full(mv),
			sm.Full(src),
			sm.Full(dst),
		)
	c := ec.NewRenameFileArgChecker().WithSrc(d1).WithDst(d2).WithFlags(fl)
	a := ec.NewFileArgumentChecker().WithRenameArg(c)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameRename(%s -> %s)", src, dst)).
		WithAction(tetragon.FileAction_FILE_RENAME).
		WithArgs(a)
}

// Rename operations that handled in kernel-space (eBPF)

func testFileRename1(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS]
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(test_path, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	fileCheckers := make([]ec.EventChecker, 3)
	fileCheckers[0] = renameRenameChecker(in_file, out_file, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_NOT_EXISTS")
	fileCheckers[1] = renameReadChecker(out_file)
	fileCheckers[2] = renameDeleteChecker(out_file)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename2(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INTERNALLY - DST_REG_FILE]
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(test_path, "test2")
	createFileInDir(t, out_file)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{test_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	fileCheckers := make([]ec.EventChecker, 3)
	fileCheckers[0] = renameRenameChecker(in_file, out_file, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_REG_FILE")
	fileCheckers[1] = renameReadChecker(out_file)
	fileCheckers[2] = renameDeleteChecker(out_file)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename3(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INSIDE - DST_NOT_EXISTS]
	inside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, inside_path)

	outside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, outside_path)

	in_file := filepath.Join(inside_path, "test1")

	out_file := filepath.Join(outside_path, "test1")
	createFileInDir(t, out_file)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{inside_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_file, in_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, in_file)
	fileRemove(t, in_file)

	fileCheckers := make([]ec.EventChecker, 3)
	fileCheckers[0] = renameRenameChecker(out_file, in_file, "MOVE_INSIDE", "SRC_REG_FILE", "DST_NOT_EXISTS")
	fileCheckers[1] = renameReadChecker(in_file)
	fileCheckers[2] = renameDeleteChecker(in_file)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename4(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INSIDE - DST_REG_FILE]
	inside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, inside_path)

	outside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, outside_path)

	in_file := filepath.Join(inside_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(outside_path, "test1")
	createFileInDir(t, out_file)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{inside_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_file, in_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, in_file)
	fileRemove(t, in_file)

	fileCheckers := make([]ec.EventChecker, 3)
	fileCheckers[0] = renameRenameChecker(out_file, in_file, "MOVE_INSIDE", "SRC_REG_FILE", "DST_REG_FILE")
	fileCheckers[1] = renameReadChecker(in_file)
	fileCheckers[2] = renameDeleteChecker(in_file)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename5(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_OUTSIDE - DST_NOT_EXISTS]
	inside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, inside_path)

	outside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, outside_path)

	in_file := filepath.Join(inside_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(outside_path, "test1")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{inside_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	noErrorFileCheckers := renameRenameChecker(in_file, out_file, "MOVE_OUTSIDE", "SRC_REG_FILE", "DST_NOT_EXISTS")
	errorFileCheckers := renameReadChecker(in_file)

	checker := ec.NewUnorderedEventChecker(noErrorFileCheckers)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)

	errorChecker := ec.NewUnorderedEventChecker(errorFileCheckers)
	err = jsonchecker.JsonTestCheck(gt, errorChecker)
	assert.Error(t, err)
}

func testFileRename6(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_OUTSIDE - DST_REG_FILE]
	inside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, inside_path)

	outside_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, outside_path)

	in_file := filepath.Join(inside_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(outside_path, "test1")
	createFileInDir(t, out_file)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{inside_path},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	noErrorFileCheckers := renameRenameChecker(in_file, out_file, "MOVE_OUTSIDE", "SRC_REG_FILE", "DST_REG_FILE")
	errorFileCheckers := renameReadChecker(in_file)

	checker := ec.NewUnorderedEventChecker(noErrorFileCheckers)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)

	errorChecker := ec.NewUnorderedEventChecker(errorFileCheckers)
	err = jsonchecker.JsonTestCheck(gt, errorChecker)
	assert.Error(t, err)
}

// Rename operations that handled in user-space

func testFileRename7(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_INSIDE - DST_NOT_EXISTS]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, in1)

	in_a := filepath.Join(in1, "a")
	iFile1 := filepath.Join(in_a, "test1")
	iFile2 := filepath.Join(in_a, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{in1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_a); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := make([]ec.EventChecker, 5)
	fileCheckers[0] = renameRenameChecker(out_a, in_a, "MOVE_INSIDE", "SRC_DIRECTORY", "DST_NOT_EXISTS")
	fileCheckers[1] = renameReadChecker(iFile1)
	fileCheckers[2] = renameReadChecker(iFile2)
	fileCheckers[3] = renameDeleteChecker(iFile1)
	fileCheckers[4] = renameDeleteChecker(iFile2)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename8(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_INSIDE - DST_DIRECTORY]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, in1)

	in_a := filepath.Join(in1, "a")
	createTestDir(t, in_a)

	iFile1 := filepath.Join(in_a, "test1")
	iFile2 := filepath.Join(in_a, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{in1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_a); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := make([]ec.EventChecker, 5)
	fileCheckers[0] = renameRenameChecker(out_a, in_a, "MOVE_INSIDE", "SRC_DIRECTORY", "DST_DIRECTORY")
	fileCheckers[1] = renameReadChecker(iFile1)
	fileCheckers[2] = renameReadChecker(iFile2)
	fileCheckers[3] = renameDeleteChecker(iFile1)
	fileCheckers[4] = renameDeleteChecker(iFile2)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename9(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_OUTSIDE - DST_NOT_EXISTS]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, in1)

	in_a := filepath.Join(in1, "a")

	iFile1 := filepath.Join(in_a, "test1")
	iFile2 := filepath.Join(in_a, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_a); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	noErrorFileCheckers := renameRenameChecker(out_a, in_a, "MOVE_OUTSIDE", "SRC_DIRECTORY", "DST_NOT_EXISTS")

	errorFileCheckers := make([]ec.EventChecker, 4)
	errorFileCheckers[0] = renameReadChecker(iFile1)
	errorFileCheckers[1] = renameReadChecker(iFile2)
	errorFileCheckers[2] = renameDeleteChecker(iFile1)
	errorFileCheckers[3] = renameDeleteChecker(iFile2)

	checker1 := ec.NewUnorderedEventChecker(noErrorFileCheckers)
	err := jsonchecker.JsonTestCheck(gt, checker1)
	assert.NoError(t, err)

	checker2 := ec.NewUnorderedEventChecker(errorFileCheckers...)
	err = jsonchecker.JsonTestCheck(gt, checker2)
	assert.Error(t, err)
}

func testFileRename10(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_OUTSIDE - DST_DIRECTORY]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_indir_%s", filepath.Base(t.Name())))
	createTestDir(t, in1)

	in_a := filepath.Join(in1, "a")
	createTestDir(t, in_a)

	iFile1 := filepath.Join(in_a, "test1")
	iFile2 := filepath.Join(in_a, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_a); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	noErrorFileCheckers := renameRenameChecker(out_a, in_a, "MOVE_OUTSIDE", "SRC_DIRECTORY", "DST_DIRECTORY")

	errorFileCheckers := make([]ec.EventChecker, 4)
	errorFileCheckers[0] = renameReadChecker(iFile1)
	errorFileCheckers[1] = renameReadChecker(iFile2)
	errorFileCheckers[2] = renameDeleteChecker(iFile1)
	errorFileCheckers[3] = renameDeleteChecker(iFile2)

	checker1 := ec.NewUnorderedEventChecker(noErrorFileCheckers)
	err := jsonchecker.JsonTestCheck(gt, checker1)
	assert.NoError(t, err)

	checker2 := ec.NewUnorderedEventChecker(errorFileCheckers...)
	err = jsonchecker.JsonTestCheck(gt, checker2)
	assert.Error(t, err)
}

func testFileRename11(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_INTERNALLY - DST_NOT_EXISTS]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in_b := filepath.Join(out1, "b")

	iFile1 := filepath.Join(in_b, "test1")
	iFile2 := filepath.Join(in_b, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_b); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := make([]ec.EventChecker, 5)
	fileCheckers[0] = renameRenameChecker(out_a, in_b, "MOVE_INTERNALLY", "SRC_DIRECTORY", "DST_NOT_EXISTS")
	fileCheckers[1] = renameReadChecker(iFile1)
	fileCheckers[2] = renameReadChecker(iFile2)
	fileCheckers[3] = renameDeleteChecker(iFile1)
	fileCheckers[4] = renameDeleteChecker(iFile2)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRename12(gt *testing.T, t *testing.T) { // [SRC_DIRECTORY - MOVE_INTERNALLY - DST_DIRECTORY]
	out1 := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out1)

	out_a := filepath.Join(out1, "a")
	createTestDir(t, out_a)

	oFile1 := filepath.Join(out_a, "test1")
	createFileInDir(t, oFile1)

	oFile2 := filepath.Join(out_a, "test2")
	createFileInDir(t, oFile2)

	in_b := filepath.Join(out1, "b")
	createTestDir(t, in_b)

	iFile1 := filepath.Join(in_b, "test1")
	iFile2 := filepath.Join(in_b, "test2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out1},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_b); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := make([]ec.EventChecker, 5)
	fileCheckers[0] = renameRenameChecker(out_a, in_b, "MOVE_INTERNALLY", "SRC_DIRECTORY", "DST_DIRECTORY")
	fileCheckers[1] = renameReadChecker(iFile1)
	fileCheckers[2] = renameReadChecker(iFile2)
	fileCheckers[3] = renameDeleteChecker(iFile1)
	fileCheckers[4] = renameDeleteChecker(iFile2)

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileRmdir(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out)

	a := filepath.Join(out, "a")

	// create a directory and we will remove that after observer starts
	if err := os.Mkdir(a, 0755); err != nil {
		t.Fatalf("Mkdir failed: %s\n", err)
	}

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	ino, dev := getInodeInfo(t, a)
	if err := os.RemoveAll(a); err != nil {
		t.Fatalf("Remove directory failed: %s\n", err)
	}

	dirChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_RMDIR).
		WithArgs(genericArgFilenameChecker(fmt.Sprintf("%s/", a), ino, dev)) // all directory names end with '/'
	checker := ec.NewUnorderedEventChecker(dirChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileMkdir(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out)

	a := filepath.Join(out, "a")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	createTestDir(t, a)
	ino, dev := getInodeInfo(t, a)

	dirChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_MKDIR).
		WithArgs(genericArgFilenameChecker(fmt.Sprintf("%s/", a), ino, dev)) // all directory names end with '/'
	checker := ec.NewUnorderedEventChecker(dirChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)

}

func readdirArgChecker(t *testing.T, path string) *ec.ReadDirArgChecker {
	ino, dev := getInodeInfo(t, path)
	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(fmt.Sprintf("%s/", path))).WithInode(i)
	return ec.NewReadDirArgChecker().WithFile(f)
}

func readdirChecker(t *testing.T, path string) *ec.ProcessFileChecker {
	return ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_READDIR).
		WithArgs(ec.NewFileArgumentChecker().WithReaddirArg(readdirArgChecker(t, path))).
		WithHook(sm.Full("iterate_dir"))
}

func testFileReadDir(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, out)

	in1 := filepath.Join(out, "a")
	createTestDir(t, in1)

	in2 := filepath.Join(out, "b")
	createTestDir(t, in2)

	in3 := filepath.Join(out, "c")
	createTestDir(t, in3)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	// method 1
	if _, err := ioutil.ReadDir(in1); err != nil {
		t.Fatalf("ioutil.ReadDir failed (%s)", err)
	}

	// method 2
	if err := filepath.Walk(in2, func(path string, info os.FileInfo, err error) error {
		return nil
	}); err != nil {
		t.Fatalf("filepath.Walk failed (%s)", err)
	}

	// method 3
	if f, err := os.Open(in3); err == nil {
		if _, err := f.Readdir(0); err != nil {
			t.Fatalf("f.Readdir failed (%s)", err)
		}
	} else {
		t.Fatalf("os.Open failed (%s)", err)
	}

	dirCheckers := make([]ec.EventChecker, 3)
	dirCheckers[0] = readdirChecker(t, in1)
	dirCheckers[1] = readdirChecker(t, in2)
	dirCheckers[2] = readdirChecker(t, in3)

	checker := ec.NewUnorderedEventChecker(dirCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileTruncate(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Truncate(oFile, 222); err != nil {
		t.Fatalf("os.Truncate failed (%s)", err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(oFile)).WithInode(i)
	o := ec.NewFileIOChecker().WithOffset(sm.Full("0")).WithSize(sm.Full("222"))
	c := ec.NewGenericFileArgChecker().WithFile(f).WithIo(o)

	fileChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("do_truncate"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

// this function returns the root filesystem of a container
func dockerIdToRootFs(cid string) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	defer cli.Close()

	cnts, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return "", err
	}

	for _, c := range cnts {
		if c.ID == cid {
			if j, err := cli.ContainerInspect(ctx, c.ID); err == nil {
				if j.GraphDriver.Name == "overlay2" {
					mergeDir, ok := j.GraphDriver.Data["MergedDir"]
					if ok {
						return mergeDir, nil
					}
				}
				return fmt.Sprintf("/proc/%d/root/", j.State.Pid), nil
			}
		}
	}
	return "", fmt.Errorf("cannot find container with ID %s", cid)
}

// this test check accessing files inside a container
func testFileReadContainerFile(gt *testing.T, t *testing.T) {
	// create a new container
	id, err := exec.Command("docker", "run", "--detach", "ubuntu:20.04", "/bin/sleep", "3650d").Output()
	if err != nil {
		t.Fatalf("failed to spawn docker container: %s", err)
	}

	containerId := strings.TrimSpace(string(id)) // get the container id
	t.Cleanup(func() {
		if err := exec.Command("docker", "rm", "--force", containerId).Run(); err != nil {
			t.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{"/etc/"},
		PathsExclude: []string{},
		Config:       make(map[string]string),
		OnlyPodFiles: true, // check only container files here
		PodSelector:  &slimv1.LabelSelector{},
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	rootDir, err := dockerIdToRootFs(containerId)
	if err != nil {
		t.Fatalf("failed to spawn docker container: %s", err)
	}

	// now we apply the existing tracing policy (i.e. /etc/) for the root filesystem of a running container
	if err := TracingPolicyInitContainerFsScanner(containerId, "", "", rootDir); err != nil {
		t.Fatalf("failed to call TracingPolicyInitContainerFsScanner(%s, %s): %s", containerId, rootDir, err)
	}

	// read /etc/shadow from inside the container
	if err := exec.Command("docker", "exec", containerId, "cat", "/etc/shadow").Run(); err != nil {
		t.Fatalf("failed to read /etc/shadow inside container %s: %s", containerId, err)
	}

	// remove any files related to the container
	if err := TracingPolicyDestroyContainerFsScanner(containerId); err != nil {
		t.Fatalf("failed to call TracingPolicyDestroyContainerFsScanner(%s): %s", containerId, err)
	}

	locChecker := ec.NewFileLocationChecker().WithType(tetragon.FileScope_CONTAINER_FILE_LOCAL).WithContainerId(sm.Full(containerId))
	fdChecker := ec.NewFileDetailsChecker().WithFilename(sm.Full("/etc/shadow")).WithLocation(locChecker)
	gfileChecker := ec.NewGenericFileArgChecker().WithFile(fdChecker)
	argChecker := ec.NewFileArgumentChecker().WithGenericArg(gfileChecker)
	readChecker := ec.NewProcessFileChecker("").WithAction(tetragon.FileAction_FILE_READ).WithArgs(argChecker)
	checker := ec.NewUnorderedEventChecker(readChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileReadMatchBinary(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
		Selectors: []v1alpha1.FileSelector{
			{
				MatchBinaries: []v1alpha1.BinarySelector{
					{
						Operator: "In",
						Values:   []string{"/usr/bin/cat"},
					},
				},
			},
		},
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if err := exec.Command("/usr/bin/cat", oFile).Run(); err != nil {
		t.Logf("failed run  /usr/bin/cat %s: %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	fileChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("rw_verify_area"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileReadMatchOperation(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{out},
		PathsExclude: []string{},
		Config:       make(map[string]string),
		Selectors: []v1alpha1.FileSelector{
			{
				MatchOperations: []v1alpha1.OperationSelector{
					{
						Operator: "In",
						Values:   []string{"FILE_READ"},
					},
				},
			},
		},
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	if _, err := os.ReadFile(oFile); err != nil {
		t.Logf("failed run os.ReadFile(%s): %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	fileChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("rw_verify_area"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testExactFileDelete(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	a := filepath.Join(out, "a")
	createFileInDir(t, a) // create the file before starting FIM

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		Paths:        []string{a}, // monitor only a specific file
		PathsExclude: []string{},
		Config:       make(map[string]string),
	}); err != nil {
		fmt.Printf("ReGenerateFimMaps failed with %s", err)
	}

	os.Remove(a)          // delete the file that we are monitoring
	createFileInDir(t, a) // create a new file with the same name

	ino, dev := getInodeInfo(t, a)
	fileChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(a, ino, dev))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func TestFileOps(t *testing.T) {
	if !kernels.MinKernelVersion("4.19.0") {
		t.Skip("File monitoring requires at least 4.19.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecFile(t, "/sample/file") // this file does not exist -- we only need to initialize all fim progs and maps
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	t.Cleanup(func() {
		TerminateFsScanner()
		ClearFIMTracingPolicies()
	})
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Run("read", func(lt *testing.T) {
		testFileRead(t, lt)
	})
	t.Run("readv", func(lt *testing.T) {
		testFileReadV(t, lt)
	})
	t.Run("preadv", func(lt *testing.T) {
		testFilePReadV(t, lt)
	})
	t.Run("preadv2", func(lt *testing.T) {
		testFilePReadV2(t, lt)
	})
	t.Run("pread64", func(lt *testing.T) {
		testFilePRead64(t, lt)
	})
	t.Run("write", func(lt *testing.T) {
		testFileWrite(t, lt)
	})
	t.Run("writev", func(lt *testing.T) {
		testFileWriteV(t, lt)
	})
	t.Run("pwritev", func(lt *testing.T) {
		testFilePWriteV(t, lt)
	})
	t.Run("pwritev2", func(lt *testing.T) {
		testFilePWriteV2(t, lt)
	})
	t.Run("pwrite64", func(lt *testing.T) {
		testFilePWrite64(t, lt)
	})
	t.Run("mmapreadpopulate", func(lt *testing.T) {
		testFileMmapReadPopulate(t, lt)
	})
	t.Run("mmapwritepopulate", func(lt *testing.T) {
		testFileMmapWritePopulate(t, lt)
	})
	t.Run("mmapread", func(lt *testing.T) {
		testFileMmapRead(t, lt)
	})
	t.Run("mmapreadwrite", func(lt *testing.T) {
		testFileMmapReadWrite(t, lt)
	})
	t.Run("mmapwrite", func(lt *testing.T) {
		testFileMmapWrite(t, lt)
	})
	t.Run("mmapwriteread", func(lt *testing.T) {
		testFileMmapWriteRead(t, lt)
	})
	t.Run("sendfile", func(lt *testing.T) {
		testSendfile(t, lt)
	})
	t.Run("copyfilerange", func(lt *testing.T) {
		testCopyFileRange(t, lt)
	})
	t.Run("splice", func(lt *testing.T) {
		testFileSplice(t, lt)
	})
	t.Run("fallocate", func(lt *testing.T) {
		testFileFallocate(t, lt)
	})
	t.Run("aiopread", func(lt *testing.T) {
		testFileAioPRead(t, lt)
	})
	t.Run("aiopreadv", func(lt *testing.T) {
		testFileAioPReadV(t, lt)
	})
	t.Run("aiopwrite", func(lt *testing.T) {
		testFileAioPWrite(t, lt)
	})
	t.Run("aiopwritev", func(lt *testing.T) {
		testFileAioPWriteV(t, lt)
	})
	t.Run("cpiouring", func(lt *testing.T) {
		testFileCpIouring(t, lt)
	})
	t.Run("catiouring", func(lt *testing.T) {
		testFileCatIouring(t, lt)
	})
	t.Run("writeiouring", func(lt *testing.T) {
		testFileWriteIouring(t, lt)
	})
	t.Run("create", func(lt *testing.T) {
		testFileCreate(t, lt)
	})
	t.Run("delete", func(lt *testing.T) {
		testFileDelete(t, lt)
	})
	t.Run("rename1", func(lt *testing.T) {
		testFileRename1(t, lt)
	})
	t.Run("rename2", func(lt *testing.T) {
		testFileRename2(t, lt)
	})
	t.Run("rename3", func(lt *testing.T) {
		testFileRename3(t, lt)
	})
	t.Run("rename4", func(lt *testing.T) {
		testFileRename4(t, lt)
	})
	t.Run("rename5", func(lt *testing.T) {
		testFileRename5(t, lt)
	})
	t.Run("rename6", func(lt *testing.T) {
		testFileRename6(t, lt)
	})
	t.Run("rename7", func(lt *testing.T) {
		testFileRename7(t, lt)
	})
	t.Run("rename8", func(lt *testing.T) {
		testFileRename8(t, lt)
	})
	t.Run("rename9", func(lt *testing.T) {
		testFileRename9(t, lt)
	})
	t.Run("rename10", func(lt *testing.T) {
		testFileRename10(t, lt)
	})
	t.Run("rename11", func(lt *testing.T) {
		testFileRename11(t, lt)
	})
	t.Run("rename12", func(lt *testing.T) {
		testFileRename12(t, lt)
	})
	t.Run("mkdir", func(lt *testing.T) {
		testFileMkdir(t, lt)
	})
	t.Run("rmdir", func(lt *testing.T) {
		testFileRmdir(t, lt)
	})
	t.Run("readdir", func(lt *testing.T) {
		testFileReadDir(t, lt)
	})
	t.Run("truncate", func(lt *testing.T) {
		testFileTruncate(t, lt)
	})
	t.Run("readcontainerfile", func(lt *testing.T) {
		testFileReadContainerFile(t, lt)
	})
	t.Run("readmatchbinary", func(lt *testing.T) {
		testFileReadMatchBinary(t, lt)
	})
	t.Run("readmatchoperation", func(lt *testing.T) {
		testFileReadMatchOperation(t, lt)
	})
	t.Run("exactfiledelete", func(lt *testing.T) {
		testExactFileDelete(t, lt)
	})
}
