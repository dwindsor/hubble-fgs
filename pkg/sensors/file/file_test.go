//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// CGO_LDFLAGS=-L$(realpath ./lib) go test -gcflags="" -c ./pkg/sensors/file -o go-tests/file.test
// sudo LD_LIBRARY_PATH=/home/apapag/hubble-fgs/lib ./go-tests/file.test --hubble-lib ./bpf/objs/ [ -test.run TestCopyFileRange ]

package file

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker"
	sm "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker/matchers/stringmatcher"
	"github.com/isovalent/hubble-fgs/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int

	testMapPrefix = "testObserver"
	workingDir    = "/tmp"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for tetragon to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	bpf.SetMapPrefix(testMapPrefix)
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	// NB: we currently seem to fail to remove the /sys/fs/bpf/testObserver
	// dir. Do so here, until we figure out a way to do it properly.
	os.RemoveAll(bpf.MapPrefixPath())
	os.Exit(exitCode)
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

func runReadWriteTest(t *testing.T, exec_path string, create_file bool, act fgs.FileAction) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 60000*time.Millisecond)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, specFname, fgsLib)
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

	fileChecker := ec.NewProcessFileChecker().
		WithAction(act).
		WithFilename(sm.Full(test_file))
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

	ctx, cancel := context.WithTimeout(context.Background(), 60000*time.Millisecond)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, in_file, out_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, specFname, fgsLib)
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

	inFileChecker := ec.NewProcessFileChecker().
		WithAction(fgs.FileAction_FILE_READ).
		WithFilename(sm.Full(in_file))
	outFileChecker := ec.NewProcessFileChecker().
		WithAction(fgs.FileAction_FILE_WRITE).
		WithFilename(sm.Full(out_file))
	checker := ec.NewUnorderedEventChecker(
		inFileChecker,
		outFileChecker,
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func runMmapTest(t *testing.T, exec_path string, act fgs.FileAction) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring requires at least 5.4.0 version")
	}

	test_path := filepath.Join(workingDir, "fim_test_dir")
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")
	fallocateFileInDir(t, test_file)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 60000*time.Millisecond)
	defer cancel()

	testBin := testutils.ContribPath(exec_path)
	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	specFname := createSpecFile(t, test_path)

	obs, err := observer.GetDefaultObserverWithLib(t, specFname, fgsLib)
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

	fileCheckerRead := ec.NewProcessFileChecker().
		WithAction(fgs.FileAction_FILE_READ).
		WithFilename(sm.Full(test_file))
	fileCheckerWrite := ec.NewProcessFileChecker().
		WithAction(fgs.FileAction_FILE_WRITE).
		WithFilename(sm.Full(test_file))
	checker := ec.NewUnorderedEventChecker(
		fileCheckerRead,
		fileCheckerWrite,
	)
	if act == fgs.FileAction_FILE_READ {
		checker = ec.NewUnorderedEventChecker(fileCheckerRead)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// tests in "hubble-fgs/contrib/tester-progs/read_write"

func TestFileRead(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/read", true, fgs.FileAction_FILE_READ)
}

func TestFileReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/readv", true, fgs.FileAction_FILE_READ)
}

func TestFilePReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/preadv", true, fgs.FileAction_FILE_READ)
}

func TestFilePReadV2(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/preadv2", true, fgs.FileAction_FILE_READ)
}

func TestFilePRead64(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pread64", true, fgs.FileAction_FILE_READ)
}

func TestFileWrite(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/write", false, fgs.FileAction_FILE_WRITE)
}

func TestFileWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/writev", false, fgs.FileAction_FILE_WRITE)
}

func TestFilePWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwritev", false, fgs.FileAction_FILE_WRITE)
}

func TestFilePWriteV2(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwritev2", false, fgs.FileAction_FILE_WRITE)
}

func TestFilePWrite64(t *testing.T) {
	runReadWriteTest(t, "tester-progs/read_write/pwrite64", false, fgs.FileAction_FILE_WRITE)
}

func TestSendfile(t *testing.T) {
	runCopyTest(t, "tester-progs/read_write/sendfile")
}

func TestCopyFileRange(t *testing.T) {
	runCopyTest(t, "tester-progs/read_write/copy_file_range")
}

// tests in hubble-fgs/contrib/tester-progs/aio

func TestFileAioPRead(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pread", true, fgs.FileAction_FILE_READ)
}

func TestFileAioPReadV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_preadv", true, fgs.FileAction_FILE_READ)
}

func TestFileAioPWrite(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pwrite", false, fgs.FileAction_FILE_WRITE)
}

func TestFileAioPWriteV(t *testing.T) {
	runReadWriteTest(t, "tester-progs/aio/aio_pwritev", false, fgs.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/open

func TestFileFallocate(t *testing.T) {
	runReadWriteTest(t, "tester-progs/open/fallocate", false, fgs.FileAction_FILE_WRITE)
}

// tests in hubble-fgs/contrib/tester-progs/splice

func TestFileSplice(t *testing.T) {
	runCopyTest(t, "tester-progs/splice/splice")
}

// tests in hubble-fgs/contrib/tester-progs/io_uring

func TestFileCatIouring(t *testing.T) {
	runReadWriteTest(t, "tester-progs/io_uring/cat_liburing", true, fgs.FileAction_FILE_READ)
}

func TestFileWriteIouring(t *testing.T) {
	runReadWriteTest(t, "tester-progs/io_uring/write_liburing", false, fgs.FileAction_FILE_WRITE)
}

func TestFileCpIouring(t *testing.T) {
	runCopyTest(t, "tester-progs/io_uring/cp_liburing")
}

// tests in hubble-fgs/contrib/tester-progs/mmap

func TestFileMmapReadPopulate(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_populate_read", fgs.FileAction_FILE_READ)
}

func TestFileMmapWritePopulate(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_populate_write", fgs.FileAction_FILE_WRITE)
}

func TestFileMmapRead(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_read", fgs.FileAction_FILE_READ)
}

func TestFileMmapReadWrite(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_read_write", fgs.FileAction_FILE_WRITE)
}

func TestFileMmapWrite(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_write", fgs.FileAction_FILE_WRITE)
}

func TestFileMmapWriteRead(t *testing.T) {
	runMmapTest(t, "tester-progs/mmap/mmap_write_read", fgs.FileAction_FILE_WRITE)
}
