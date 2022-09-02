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
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	workingDir = "/tmp"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorFile")
	os.Exit(ec)
}

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
		"msg_file_path": {reflect.TypeOf(fileapi.MsgFilePath{})},
		"msg_fs_info":   {reflect.TypeOf(fileapi.MsgFsInfo{})},
		"msg_file_ops":  {reflect.TypeOf(fileapi.MsgFileEvent{})},
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

	return stat.Ino, fmt.Sprintf("%d:%d", getDevMajor(stat.Dev), getDevMinor(stat.Dev))
}

func genericArgFilenameChecker(fileName string, ino uint64, dev string) *ec.FileArgumentChecker {
	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithFilename(sm.Full(fileName)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)
	return ec.NewFileArgumentChecker().WithGenericArg(c)
}

func runReadWriteTest(t *testing.T, exec_path string, create_file bool, act tetragon.FileAction) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")
	if create_file == true {
		createFileInDir(t, test_file)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	ino, dev := getInodeInfo(t, test_file)
	fileChecker := ec.NewProcessFileChecker().
		WithAction(act).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func runCopyTest(t *testing.T, exec_path string) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	out_file := filepath.Join(test_path, "test2")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, in_file, out_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	in_ino, in_dev := getInodeInfo(t, in_file)
	inFileChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(in_file, in_ino, in_dev))
	out_ino, out_dev := getInodeInfo(t, out_file)
	outFileChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(out_file, out_ino, out_dev))
	checker := ec.NewUnorderedEventChecker(
		inFileChecker,
		outFileChecker,
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func runMmapTest(t *testing.T, exec_path string, act tetragon.FileAction) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")
	fallocateFileInDir(t, test_file)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	ino, dev := getInodeInfo(t, test_file)
	fileCheckerRead := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	fileCheckerWrite := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(
		fileCheckerRead,
		fileCheckerWrite,
	)
	if act == tetragon.FileAction_FILE_READ {
		checker = ec.NewUnorderedEventChecker(fileCheckerRead)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// tests in "hubble-fgs/contrib/tester-progs/read_write"

func TestFileRead(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/read", true, tetragon.FileAction_FILE_READ)
}

func TestFileReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/readv", true, tetragon.FileAction_FILE_READ)
}

func TestFilePReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/preadv", true, tetragon.FileAction_FILE_READ)
}

func TestFilePReadV2(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/preadv2", true, tetragon.FileAction_FILE_READ)
}

func TestFilePRead64(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pread64", true, tetragon.FileAction_FILE_READ)
}

func TestFileWrite(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/write", false, tetragon.FileAction_FILE_WRITE)
}

func TestFileWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/writev", false, tetragon.FileAction_FILE_WRITE)
}

func TestFilePWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwritev", false, tetragon.FileAction_FILE_WRITE)
}

func TestFilePWriteV2(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwritev2", false, tetragon.FileAction_FILE_WRITE)
}

func TestFilePWrite64(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwrite64", false, tetragon.FileAction_FILE_WRITE)
}

func TestSendfile(t *testing.T) {
	runCopyTest(t, "tester-progs/read_write/sendfile")
}

func TestCopyFileRange(t *testing.T) {
	runCopyTest(t, "tester-progs/read_write/copy_file_range")
}

// tests in hubble-fgs/contrib/tester-progs/aio

func TestFileAioPRead(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pread", true, tetragon.FileAction_FILE_READ)
}

func TestFileAioPReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_preadv", true, tetragon.FileAction_FILE_READ)
}

func TestFileAioPWrite(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pwrite", false, tetragon.FileAction_FILE_WRITE)
}

func TestFileAioPWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pwritev", false, tetragon.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/open

func TestFileFallocate(t *testing.T) {
	runReadWriteTest(t, "tester-progs/open/fallocate", false, tetragon.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/splice

func TestFileSplice(t *testing.T) {
	runCopyTest(t, "tester-progs/splice/splice")
}

// tests in hubble-fgs/contrib/tester-progs/io_uring

func TestFileCatIouring(t *testing.T) {
	runReadWriteTest(t, "tester-progs/io_uring/cat_liburing", true, tetragon.FileAction_FILE_READ)
}

func TestFileWriteIouring(t *testing.T) {
	runReadWriteTest(t, "tester-progs/io_uring/write_liburing", false, tetragon.FileAction_FILE_WRITE)
}

func TestFileCpIouring(t *testing.T) {
	runCopyTest(t, "tester-progs/io_uring/cp_liburing")
}

// tests in hubble-fgs/contrib/tester-progs/mmap

func TestFileMmapReadPopulate(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_populate_read", tetragon.FileAction_FILE_READ)
}

func TestFileMmapWritePopulate(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_populate_write", tetragon.FileAction_FILE_WRITE)
}

func TestFileMmapRead(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_read", tetragon.FileAction_FILE_READ)
}

func TestFileMmapReadWrite(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_read_write", tetragon.FileAction_FILE_WRITE)
}

func TestFileMmapWrite(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_write", tetragon.FileAction_FILE_WRITE)
}

func TestFileMmapWriteRead(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_write_read", tetragon.FileAction_FILE_WRITE)
}

func TestFileDelete(t *testing.T) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	in_file := filepath.Join(test_path, "test1")
	createFileInDir(t, in_file)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// get inode before removing the file
	ino, dev := getInodeInfo(t, in_file)

	errOp := os.Remove(in_file)
	if errOp != nil {
		t.Errorf("os.Remove failed (%s)", errOp)
	}

	inFileChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(in_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(inFileChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
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

func TestFileCreate(t *testing.T) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fp1 := filepath.Join(test_path, "newfile1.txt")
	fp2 := filepath.Join(test_path, "newfile2.txt")

	fileCreate(t, test_path)

	ino1, dev1 := getInodeInfo(t, fp1)
	ino2, dev2 := getInodeInfo(t, fp2)

	perm1, uid1, gid1 := getFilePermsUidGui(t, fp1)
	perm2, uid2, gid2 := getFilePermsUidGui(t, fp2)

	fileCleanup(t, test_path)

	file1CreateChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1)).
		WithPermissions(sm.Full(perm1)).
		WithUid(sm.Full(uid1)).
		WithGid(sm.Full(gid1))
	file2CreateChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2)).
		WithPermissions(sm.Full(perm2)).
		WithUid(sm.Full(uid2)).
		WithGid(sm.Full(gid2))
	file2WriteChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	file1DeleteChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1))
	file2DeleteChecker := ec.NewProcessFileChecker().
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	checker := ec.NewUnorderedEventChecker(
		file1CreateChecker,
		file2CreateChecker,
		file2WriteChecker,
		file1DeleteChecker,
		file2DeleteChecker,
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadFileSensor(t *testing.T) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	specFname := createSpecFile(t, test_path)

	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	sensorProgs := []tus.SensorProg{
		0: tus.SensorProg{Name: "vfs_fallocate", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "filemap_fault", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "filemap_map_pages", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "filemap_page_mkwrite", Type: ebpf.Kprobe},
		4: tus.SensorProg{Name: "rw_verify_area", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "security_path_unlink", Type: ebpf.Kprobe},
		6: tus.SensorProg{Name: "do_dentry_open", Type: ebpf.Kprobe},

		// base sensor
		7: tus.SensorProg{Name: "event_execve", Type: ebpf.TracePoint},
		8: tus.SensorProg{Name: "event_exit", Type: ebpf.TracePoint},
		9: tus.SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
	}

	sensorMaps := []tus.SensorMap{
		// all programs
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},

		// base only
		tus.SensorMap{Name: "execve_map_stats", Progs: []uint{7, 8, 9}},

		// all but base
		tus.SensorMap{Name: "lpm_trie_map_alloc", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

		// separate maps
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{0}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{1}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{2}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{3}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{4}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{5}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{6}},

		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{0}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{1}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{2}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{3}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{4}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{5}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{6}},

		tus.SensorMap{Name: "file_heap_map", Progs: []uint{0}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{1}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{2}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{3}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{4}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{5}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{6}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)

}
