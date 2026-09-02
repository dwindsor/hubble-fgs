// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// go test -tags sudo_tests -gcflags="" -c ./pkg/sensors/file -o go-tests/file.test
// sudo ./go-tests/file.test --bpf-lib ./bpf/objs/ [ -test.run TestCopyFileRange ]

//go:build sudo_tests

package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	check "github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/jsonchecker"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"

	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	workingDir = "/mnt"
)

var (
	protoToProg = map[string]string{
		// vfs_rename
		"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)": "419",
		"vfs_rename(struct renamedata*)": "512",
		// security_inode_setattr
		"security_inode_setattr(struct dentry*, struct iattr*)":                         "419",
		"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)": "60",
		"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)":      "63",
		// vfs_unlink
		"vfs_unlink(struct inode*, struct dentry*, struct inode**)":                             "419",
		"vfs_unlink(struct user_namespace*, struct inode*, struct dentry*, struct inode**)":     "512",
		"vfs_unlink(struct mnt_idmap*, struct inode*, struct dentry*, struct inode**)":          "63",
		"vfs_unlink(struct mnt_idmap*, struct inode*, struct dentry*, struct delegated_inode*)": "70",
		// vfs_mkdir
		"vfs_mkdir(struct inode*, struct dentry*, umode_t)":                                             "419",
		"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)":                     "512",
		"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)":                          "63",
		"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t, struct delegated_inode*)": "70",
		// io_read
		"io_read(struct io_kiocb*, int)":                            "510",
		"io_read(struct io_kiocb*, bool, struct io_comp_state*)":    "59",
		"io_read(struct io_kiocb*, bool)":                           "57",
		"io_read(struct io_kiocb*, struct io_kiocb**, bool)":        "55",
		"io_read(struct io_kiocb*, const struct sqe_submit*, bool)": "51",
		// vfs_mkdir retprobe
		"int vfs_mkdir(struct inode*, struct dentry*, umode_t)":                                                        "vfs_mkdir_exit",
		"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)":                                "vfs_mkdir_exit",
		"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)":                                     "vfs_mkdir_exit",
		"struct dentry* vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)":                          "vfs_mkdir_exit_v614",
		"struct dentry* vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t, struct delegated_inode*)": "vfs_mkdir_exit_v614",
		// vfs_mknod
		"vfs_mknod(struct inode*, struct dentry*, umode_t, dev_t)":                                             "419",
		"vfs_mknod(struct user_namespace*, struct inode*, struct dentry*, umode_t, dev_t)":                     "512",
		"vfs_mknod(struct mnt_idmap*, struct inode*, struct dentry*, umode_t, dev_t)":                          "63",
		"vfs_mknod(struct mnt_idmap*, struct inode*, struct dentry*, umode_t, dev_t, struct delegated_inode*)": "70",
	}
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
	toCheck := map[string][]any{
		"inode_key":                  {fileapi.InodeKey{}},
		"inode_val":                  {fileapi.InodeVal{}},
		"msg_file_path":              {fileapi.MsgFilePath{}},
		"msg_fs_info":                {fileapi.MsgFsInfo{}},
		"msg_file_ops":               {fileapi.MsgFileEvent{}},
		"msg_file_split_path":        {fileapi.MsgFileSplitPath{}},
		"msg_rename_elem":            {fileapi.MsgRenameElem{}},
		"msg_file_rename_ops":        {fileapi.MsgFileRenameEvent{}},
		"msg_link_elem":              {fileapi.MsgLinkElem{}},
		"msg_file_link_ops":          {fileapi.MsgFileLinkEvent{}},
		"file_config_map_value":      {fileapi.FileConfigMapValue{}},
		"file_exec_config_map_value": {fileapi.FileExecConfigMapValue{}},
		"lpm_key":                    {fileapi.LPMMapKey{}},
		"lpm_val":                    {fileapi.LPMMapValue{}},
		"digest_key":                 {fileapi.DigestKey{}},
		"file_exec_stats":            {fileapi.FileExecStats{}},
		"file_sel_caps":              {fileapi.SelCaps{}},
		"ns_filter_key":              {fileapi.NsFilterKey{}},
		"file_errors":                {fileapi.FileErrors{}},
		"pattern_val":                {fileapi.PatternValue{}},
		"full_path":                  {fileapi.FullPath{}},
		"msg_file_path_simple":       {fileapi.MsgFilePathSimple{}},
		"msg_file_symlink_ops":       {fileapi.MsgFileSymlinkEvent{}},
		"msg_file_openraw_ops":       {fileapi.MsgFileOpenRawEvent{}},
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

func newSpecFile(t *testing.T, test_path string, template string) string {
	specData := map[string]string{
		"MatchedPath": test_path,
	}

	specFname, err := testutils.GetSpecFromTemplate(template, specData)
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

func createSpecFile(t *testing.T, test_path string) string {
	return newSpecFile(t, test_path, "file_monitoring.yaml.tmpl")
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
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(fileName)).WithInode(i).WithLocation(l)
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(exec_path))

	ino, dev := getInodeInfo(t, test_file)
	openChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(act).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(openChecker, fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testDlopenRead(gt *testing.T, t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	// this should match the path that we use in contrib/tester-progs/dlopen.c
	libFile := "/lib/x86_64-linux-gnu/libm.so.6"

	if _, err := os.Stat(libFile); errors.Is(err, os.ErrNotExist) {
		t.Skip("/lib/x86_64-linux-gnu/libm.so.6 does not exist")
	}

	execPath := "contrib/tester-progs/dlopen"
	testBin := testutils.RepoRootPath(execPath)
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: libFile,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	ino, dev := getInodeInfo(t, libFile)
	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(libFile, ino, dev))
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(exec_path))

	in_ino, in_dev := getInodeInfo(t, in_file)
	inOpenChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(genericArgFilenameChecker(in_file, in_ino, in_dev))
	inFileChecker := ec.NewProcessFileChecker("inFile").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(in_file, in_ino, in_dev))
	out_ino, out_dev := getInodeInfo(t, out_file)
	outOpenChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(genericArgFilenameChecker(out_file, out_ino, out_dev))
	outFileChecker := ec.NewProcessFileChecker("outFile").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(out_file, out_ino, out_dev))
	checker := ec.NewUnorderedEventChecker(
		inOpenChecker,
		inFileChecker,
		outOpenChecker,
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(exec_path))

	ino, dev := getInodeInfo(t, test_file)
	openChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	fileCheckerRead := ec.NewProcessFileChecker("readChecker").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	fileCheckerWrite := ec.NewProcessFileChecker("writeChecker").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(
		openChecker,
		fileCheckerRead,
		fileCheckerWrite,
	)
	if act == tetragon.FileAction_FILE_READ {
		checker = ec.NewUnorderedEventChecker(openChecker, fileCheckerRead)
	}

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

// tests in "hubble-fgs/contrib/tester-progs/read_write"

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

func testFilePollingIouring(gt *testing.T, t *testing.T) {
	// io_uring introduced in kernel 5.10: https://lwn.net/Articles/810414/
	// but this test requires kernels >= 5.10.
	if !kernels.MinKernelVersion("5.10.0") {
		t.Skip("File monitoring (sq_poll) requires at least 5.10.0 version")
	}

	// temporary check for buggy kernel
	// https://lore.kernel.org/io-uring/Zg1aVQVgBO3Rw0_4@tinh.kkourt.io/t/#u
	execPath := "contrib/tester-progs/io_uring/sq_poll"
	testBin := testutils.RepoRootPath(execPath)
	out, err := exec.Command(testBin, "/tmp/fim_my_sq_poll_test_file").CombinedOutput()
	os.Remove("/tmp/fim_my_sq_poll_test_file")
	if err != nil {
		if strings.Contains(string(out), "Bad file descriptor") {
			t.Skip("buggy kernel")
		}
		t.Fatalf("failed to execute sq_poll: %s", err)
	}

	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	test_file := filepath.Join(test_path, "test1")

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	testCmd := exec.CommandContext(ctx, testBin, test_file)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(execPath)))

	ino, dev := getInodeInfo(t, test_file)
	fileWriteChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev)).
		WithHook(sm.Full("security_file_permission"))
	fileReadChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(test_file, ino, dev)).
		WithHook(sm.Full("security_file_permission"))
	checker := ec.NewUnorderedEventChecker(
		fileWriteChecker,
		fileWriteChecker,
		fileReadChecker,
		fileReadChecker,
	)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	// get inode before removing the file
	ino, dev := getInodeInfo(t, in_file)

	errOp := os.Remove(in_file)
	if errOp != nil {
		t.Errorf("os.Remove failed (%s)", errOp)
	}

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	inFileChecker := ec.NewProcessFileChecker("inFileChecker").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(in_file, ino, dev))
	checker := ec.NewUnorderedEventChecker(inFileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
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
	uID := fileStats.Sys().(*syscall.Stat_t).Uid
	gID := fileStats.Sys().(*syscall.Stat_t).Gid

	return permStr, strconv.FormatUint(uint64(uID), 10), strconv.FormatUint(uint64(gID), 10)
}

func testFileCreate(gt *testing.T, t *testing.T) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, test_path)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	fp1 := filepath.Join(test_path, "newfile1.txt")
	fp2 := filepath.Join(test_path, "newfile2.txt")

	fileCreate(t, test_path)

	ino1, dev1 := getInodeInfo(t, fp1)
	ino2, dev2 := getInodeInfo(t, fp2)

	perm1, uid1, gid1 := getFilePermsUidGui(t, fp1)
	perm2, uid2, gid2 := getFilePermsUidGui(t, fp2)

	fileCleanup(t, test_path)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	file1CreateChecker := ec.NewProcessFileChecker("file1Create").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1)).
		WithPermissions(sm.Full(perm1)).
		WithUid(sm.Full(uid1)).
		WithGid(sm.Full(gid1))
	file2CreateChecker := ec.NewProcessFileChecker("file2Create").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2)).
		WithPermissions(sm.Full(perm2)).
		WithUid(sm.Full(uid2)).
		WithGid(sm.Full(gid2))
	file2WriteChecker := ec.NewProcessFileChecker("file2Write").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	file1DeleteChecker := ec.NewProcessFileChecker("file1Delete").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp1, ino1, dev1))
	file2DeleteChecker := ec.NewProcessFileChecker("file2Delete").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(genericArgFilenameChecker(fp2, ino2, dev2))
	checker := ec.NewUnorderedEventChecker(
		file1CreateChecker,
		file2CreateChecker,
		file2WriteChecker,
		file1DeleteChecker,
		file2DeleteChecker,
	)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func getProgSuffix(t *testing.T, spec *btf.Spec, fnName string, retprobe bool) string {
	proto, err := fgsBTF.GetFuncProto(spec, fnName, retprobe)
	if err != nil {
		t.Fatalf("GetFuncProto function: %s error: %s", fnName, err)
	}

	prog, ok := protoToProg[proto]
	if !ok {
		t.Fatalf("%s program not found", fnName)
	}

	return prog
}

func TestLoadFileSensor(t *testing.T) {
	test_path := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	specFname := createSpecFile(t, test_path)

	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	b := base.GetInitialSensorTest(t)
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, specFname, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithBase error: %s", err)
	}
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})

	spec, err := ossBTF.NewBTF()
	if err != nil || spec == nil {
		t.Fatalf("GetCachedBTF error: %s", err)
	}

	mkdirVerSuffix := getProgSuffix(t, spec, "vfs_mkdir", false)
	unlinkVerSuffix := getProgSuffix(t, spec, "vfs_unlink", false)
	attrVerSuffix := getProgSuffix(t, spec, "security_inode_setattr", false)
	renameVerSuffix := getProgSuffix(t, spec, "vfs_rename", false)
	retprobeMkdir := getProgSuffix(t, spec, "vfs_mkdir", true)
	mknodVerSuffix := getProgSuffix(t, spec, "vfs_mknod", false)

	sensorProgs := []tus.SensorProg{
		0:  tus.SensorProg{Name: "vfs_fallocate", Type: ebpf.Kprobe},
		1:  tus.SensorProg{Name: "filemap_fault", Type: ebpf.Kprobe},
		2:  tus.SensorProg{Name: "filemap_map_pages", Type: ebpf.Kprobe},
		3:  tus.SensorProg{Name: "filemap_page_mkwrite", Type: ebpf.Kprobe},
		4:  tus.SensorProg{Name: "security_file_permission", Type: fm.If(utils.SupportFentry(), ebpf.Tracing, ebpf.Kprobe)},
		5:  tus.SensorProg{Name: fmt.Sprintf("vfs_unlink_v%s", unlinkVerSuffix), Type: ebpf.Kprobe},
		6:  tus.SensorProg{Name: "finish_open", Type: ebpf.Kprobe},
		7:  tus.SensorProg{Name: "security_inode_rmdir", Type: ebpf.Kprobe},
		8:  tus.SensorProg{Name: fmt.Sprintf("vfs_mkdir_v%s", mkdirVerSuffix), Type: ebpf.Kprobe},
		9:  tus.SensorProg{Name: retprobeMkdir, Type: ebpf.Kprobe},
		10: tus.SensorProg{Name: "security_path_rename", Type: ebpf.Kprobe},
		11: tus.SensorProg{Name: "security_path_rename_exit", Type: ebpf.Kprobe},
		12: tus.SensorProg{Name: fmt.Sprintf("vfs_rename_v%s", renameVerSuffix), Type: ebpf.Kprobe},
		13: tus.SensorProg{Name: "vfs_rename_exit", Type: ebpf.Kprobe},
		14: tus.SensorProg{Name: "vfs_open", Type: ebpf.Kprobe},
		15: tus.SensorProg{Name: "iterate_dir", Type: ebpf.Kprobe},
		16: tus.SensorProg{Name: fmt.Sprintf("security_inode_setattr_v%s", attrVerSuffix), Type: ebpf.Kprobe},
		17: tus.SensorProg{Name: "security_bprm_check", Type: ebpf.Kprobe},
		18: tus.SensorProg{Name: "security_inode_link", Type: ebpf.Kprobe},
		19: tus.SensorProg{Name: "security_file_open", Type: ebpf.Kprobe},
		20: tus.SensorProg{Name: fmt.Sprintf("vfs_mknod_v%s", mknodVerSuffix), Type: ebpf.Kprobe},
		21: tus.SensorProg{Name: "vfs_mknod_exit", Type: ebpf.Kprobe},
	}

	if fm.SupportIoUring() {
		ioUringSuffix := getProgSuffix(t, spec, "io_read", false)
		ioUringProgs := []tus.SensorProg{
			{Name: fmt.Sprintf("io_read_entry_%s", ioUringSuffix), Type: ebpf.Kprobe},
			{Name: "io_read_exit", Type: ebpf.Kprobe},
			{Name: fmt.Sprintf("io_write_entry_%s", ioUringSuffix), Type: ebpf.Kprobe},
			{Name: "io_write_exit", Type: ebpf.Kprobe},
		}
		sensorProgs = append(sensorProgs, ioUringProgs...)
	}

	if !kernels.MinKernelVersion("4.19.0") {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "fsnotify", Type: ebpf.Kprobe})
	}

	sensorMaps := []tus.SensorMap{
		// all programs that generate events
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 9, 13, 14, 15, 16, 17, 18, 19, 21}},
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 17, 18, 19, 20}},

		// shared maps
		tus.SensorMap{Name: "lpm_trie_map_alloc", Progs: []uint{6, 8, 13, 14, 18, 19, 20}},
		tus.SensorMap{Name: "hash_map_inode_alloc", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}},
		tus.SensorMap{Name: "mk_retprobe_map", Progs: []uint{8, 9, 20, 21}},
		tus.SensorMap{Name: "rename_retprobe_map", Progs: []uint{10, 11, 12, 13}},
		tus.SensorMap{Name: "file_ops_maps", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 17, 18, 19, 20}},
		tus.SensorMap{Name: "lpm_trie_heap_key", Progs: []uint{6, 8, 13, 14, 18, 19, 20}},
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{6, 8, 12, 14, 18, 19, 20}},
		tus.SensorMap{Name: "file_heap_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18, 19, 20, 21}},
		tus.SensorMap{Name: "vfs_rename_info_heap", Progs: []uint{10, 12}},
		tus.SensorMap{Name: "file_rename_heap_map", Progs: []uint{13}},
		tus.SensorMap{Name: "file_val_map", Progs: []uint{6, 9, 13, 14, 18, 21}},
	}

	if utils.SupportProcessTree() {
		pstreeMaps := []tus.SensorMap{
			{Name: "tg_conf_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 17, 18, 19, 20}},
		}
		sensorMaps = append(sensorMaps, pstreeMaps...)
	}

	if fm.SupportIoUring() {
		ioUringMaps := []tus.SensorMap{
			{Name: "io_uring_map", Progs: []uint{0, 1, 2, 3, 4, 22, 23, 24, 25}},
			{Name: "io_uring_retprobe_map", Progs: []uint{22, 23, 24, 25}},
		}
		sensorMaps = append(sensorMaps, ioUringMaps...)
	} else {
		ioUringMaps := []tus.SensorMap{
			{Name: "io_uring_map", Progs: []uint{0, 1, 2, 3, 4}},
		}
		sensorMaps = append(sensorMaps, ioUringMaps...)
	}

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func createSpecEnforceFile(t *testing.T, test_path string, operation string) string {
	specData := map[string]string{
		"MatchedPath":      test_path,
		"MatchedOperation": operation,
	}

	specFname, err := testutils.GetSpecFromTemplate("file_monitoring_enforce.yaml.tmpl", specData)
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

func TestFileEnforceCreate(t *testing.T) {
	if !utils.SupportEnforcement() {
		t.Skip("Kernel does not support file enforcement")
	}

	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecEnforceFile(t, fmt.Sprintf("%s/", out), "FILE_CREATE")
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFname, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	oFile := filepath.Join(out, "test1")
	_, err = os.Create(oFile) // we expect this to fail
	assert.Error(t, err)

	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile))
	c := ec.NewGenericFileArgChecker().WithFile(f)
	o := ec.NewFileOperationListMatcher().
		WithOperator(lm.Ordered).
		WithValues(
			ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_BLOCK),
		)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_CREATE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_inode_create")).
		WithOperation(o)
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestFileEnforceWrite(t *testing.T) {
	if !utils.SupportEnforcement() {
		t.Skip("Kernel does not support file enforcement")
	}

	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecEnforceFile(t, fmt.Sprintf("%s/", out), "FILE_WRITE")
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFname, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	oFile := filepath.Join(out, "test1")
	file, err := os.Create(oFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.WriteString("some random test data here")
	assert.Error(t, err) // we expect this to fail

	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile))
	c := ec.NewGenericFileArgChecker().WithFile(f)
	o := ec.NewFileOperationListMatcher().
		WithOperator(lm.Ordered).
		WithValues(
			ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_BLOCK),
		)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission")).
		WithOperation(o)
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestFileEnforceExec(t *testing.T) {
	if !utils.SupportEnforcement() {
		t.Skip("Kernel does not support file enforcement")
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/test.sh")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecEnforceFile(t, testBin, "FILE_EXEC")
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFname, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	assert.Error(t, exec.Command(testBin).Run()) // we expect this to fail

	ino, dev := getInodeInfo(t, testBin)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(testBin)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)
	o := ec.NewFileOperationListMatcher().
		WithOperator(lm.Ordered).
		WithValues(
			ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_BLOCK),
		)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_EXEC).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_bprm_check")).
		WithOperation(o)
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
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

func renameDeleteChecker(t *testing.T, f string) *ec.ProcessFileChecker {
	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d := ec.NewFileDetailsChecker().WithStr(sm.Full(f)).WithLocation(l)
	g := ec.NewGenericFileArgChecker().WithFile(d)
	a := ec.NewFileArgumentChecker().WithGenericArg(g)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameDelete(%s)", f)).
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_DELETE).
		WithArgs(a)
}

func renameReadChecker(t *testing.T, f string) *ec.ProcessFileChecker {
	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d := ec.NewFileDetailsChecker().WithStr(sm.Full(f)).WithLocation(l)
	g := ec.NewGenericFileArgChecker().WithFile(d)
	a := ec.NewFileArgumentChecker().WithGenericArg(g)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameRead(%s)", f)).
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(a)
}

func renameOpenChecker(t *testing.T, f string) *ec.ProcessFileChecker {
	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	fl := ec.NewStringListMatcher().WithOperator(lm.Unordered).WithValues(sm.Full("O_RDONLY"))
	d := ec.NewFileDetailsChecker().WithStr(sm.Full(f)).WithLocation(l).WithOpenFlags(fl)
	g := ec.NewGenericFileArgChecker().WithFile(d)
	a := ec.NewFileArgumentChecker().WithGenericArg(g)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameOpen(%s)", f)).
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(a).
		WithHook(sm.Full("security_file_open"))
}

func renameRenameChecker(t *testing.T, file_a, file_b, mv, src, dst string) *ec.ProcessFileChecker {
	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d1 := ec.NewFileDetailsChecker().WithStr(sm.Full(file_a)).WithLocation(l)
	d2 := ec.NewFileDetailsChecker().WithStr(sm.Full(file_b)).WithLocation(l)
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
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_RENAME).
		WithArgs(a)
}

func renameRenameCheckerNoFlags(file_a, file_b string) *ec.ProcessFileChecker {
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	d1 := ec.NewFileDetailsChecker().WithStr(sm.Full(file_a)).WithLocation(l)
	d2 := ec.NewFileDetailsChecker().WithStr(sm.Full(file_b)).WithLocation(l)
	c := ec.NewRenameFileArgChecker().WithSrc(d1).WithDst(d2)
	a := ec.NewFileArgumentChecker().WithRenameArg(c)

	return ec.NewProcessFileChecker(fmt.Sprintf("renameRename(%s -> %s)", file_a, file_b)).
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, in_file, out_file, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_NOT_EXISTS"),
		renameOpenChecker(t, out_file),
		renameReadChecker(t, out_file),
		renameDeleteChecker(t, out_file),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: test_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, in_file, out_file, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_REG_FILE"),
		renameOpenChecker(t, out_file),
		renameReadChecker(t, out_file),
		renameDeleteChecker(t, out_file),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inside_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_file, in_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, in_file)
	fileRemove(t, in_file)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_file, in_file, "MOVE_INSIDE", "SRC_REG_FILE", "DST_NOT_EXISTS"),
		renameOpenChecker(t, in_file),
		renameReadChecker(t, in_file),
		renameDeleteChecker(t, in_file),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inside_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_file, in_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, in_file)
	fileRemove(t, in_file)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_file, in_file, "MOVE_INSIDE", "SRC_REG_FILE", "DST_REG_FILE"),
		renameOpenChecker(t, in_file),
		renameReadChecker(t, in_file),
		renameDeleteChecker(t, in_file),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inside_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	noErrorFileCheckers := renameRenameChecker(t, in_file, out_file, "MOVE_OUTSIDE", "SRC_REG_FILE", "DST_NOT_EXISTS")
	errorFileCheckers := renameReadChecker(t, in_file)

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inside_path,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(in_file, out_file); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	fileRead(t, out_file)
	fileRemove(t, out_file)

	noErrorFileCheckers := renameRenameChecker(t, in_file, out_file, "MOVE_OUTSIDE", "SRC_REG_FILE", "DST_REG_FILE")
	errorFileCheckers := renameReadChecker(t, in_file)

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: in1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_a); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_a, in_a, "MOVE_INSIDE", "SRC_DIRECTORY", "DST_NOT_EXISTS"),
		renameOpenChecker(t, iFile1),
		renameReadChecker(t, iFile1),
		renameOpenChecker(t, iFile2),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: in1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_a); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_a, in_a, "MOVE_INSIDE", "SRC_DIRECTORY", "DST_DIRECTORY"),
		renameOpenChecker(t, iFile1),
		renameReadChecker(t, iFile1),
		renameOpenChecker(t, iFile2),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_a); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	noErrorFileCheckers := renameRenameChecker(t, out_a, in_a, "MOVE_OUTSIDE", "SRC_DIRECTORY", "DST_NOT_EXISTS")

	errorFileCheckers := []ec.EventChecker{
		renameReadChecker(t, iFile1),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_a); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	noErrorFileCheckers := renameRenameChecker(t, out_a, in_a, "MOVE_OUTSIDE", "SRC_DIRECTORY", "DST_DIRECTORY")

	errorFileCheckers := []ec.EventChecker{
		renameReadChecker(t, iFile1),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(out_a, in_b); err != nil {
		t.Fatalf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_a, in_b, "MOVE_INTERNALLY", "SRC_DIRECTORY", "DST_NOT_EXISTS"),
		renameOpenChecker(t, iFile1),
		renameReadChecker(t, iFile1),
		renameOpenChecker(t, iFile2),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := syscall.Rename(out_a, in_b); err != nil {
		t.Fatalf("syscall.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	fileRead(t, iFile1)
	fileRead(t, iFile2)
	fileRemove(t, iFile1)
	fileRemove(t, iFile2)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, out_a, in_b, "MOVE_INTERNALLY", "SRC_DIRECTORY", "DST_DIRECTORY"),
		renameOpenChecker(t, iFile1),
		renameReadChecker(t, iFile1),
		renameOpenChecker(t, iFile2),
		renameReadChecker(t, iFile2),
		renameDeleteChecker(t, iFile1),
		renameDeleteChecker(t, iFile2),
	}

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

// This test checks 2 things in the case when we monitor a specific file (not a directory):
// 1. rename the file that we care in and out of the monitored files
// 2. rename a file that we don't care but is in the same directory
// In the first case we should continue monitor that in all cases and
// in the second case we should not report anything.
func testFileRename13(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS]
	testPath := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testPath)

	inFile1 := filepath.Join(testPath, "in1")
	createFileInDir(t, inFile1)

	inFile2 := filepath.Join(testPath, "in2")
	createFileInDir(t, inFile2)

	outFile1 := filepath.Join(testPath, "out1")
	outFile2 := filepath.Join(testPath, "out2")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inFile1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(inFile1, outFile1); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}
	if err := os.Rename(outFile1, inFile1); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}
	fileRead(t, inFile1)

	if err := os.Rename(inFile2, outFile2); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}
	if err := os.Rename(outFile2, inFile2); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}
	fileRead(t, inFile2)

	// we should see these events
	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, inFile1, outFile1, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_NOT_EXISTS"),
		renameRenameChecker(t, outFile1, inFile1, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_NOT_EXISTS"),
		renameOpenChecker(t, inFile1),
		renameReadChecker(t, inFile1),
	}
	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)

	// we should *NOT* see these events
	fileCheckersFail := []ec.EventChecker{
		renameRenameCheckerNoFlags(inFile2, outFile2),
		renameRenameCheckerNoFlags(outFile2, inFile2),
		renameReadChecker(t, inFile2),
	}
	checkerFail := ec.NewUnorderedEventChecker(fileCheckersFail...)
	err = jsonchecker.JsonTestCheck(gt, checkerFail)
	assert.Error(t, err)
}

// This test check the case where we monitor a specific file but
// the file does not exist when we start monitoring.
func testFileRename14(gt *testing.T, t *testing.T) { // [SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS]
	testPath := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testPath)

	inFile1 := filepath.Join(testPath, "in1")
	createFileInDir(t, inFile1)

	inFile2 := filepath.Join(testPath, "in2")
	createFileInDir(t, inFile2)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: inFile1,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Rename(inFile2, inFile1); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}
	fileRead(t, inFile1)

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, inFile2, inFile1, "MOVE_INTERNALLY", "SRC_REG_FILE", "DST_REG_FILE"),
		renameOpenChecker(t, inFile1),
		renameReadChecker(t, inFile1),
	}
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	ino, dev := getInodeInfo(t, a)
	if err := os.RemoveAll(a); err != nil {
		t.Fatalf("Remove directory failed: %s\n", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	dirChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_RMDIR).
		WithArgs(genericArgFilenameChecker(fmt.Sprintf("%s/", a), ino, dev)) // all directory names end with '/'
	checker := ec.NewUnorderedEventChecker(dirChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testFileMkdir(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, fmt.Sprintf("fim_test_outdir_%s", filepath.Base(t.Name())))
	createTestDir(t, out)

	a := filepath.Join(out, "a")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	createTestDir(t, a)
	ino, dev := getInodeInfo(t, a)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	dirChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_MKDIR).
		WithArgs(genericArgFilenameChecker(fmt.Sprintf("%s/", a), ino, dev)) // all directory names end with '/'
	checker := ec.NewUnorderedEventChecker(dirChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)

}

func readdirArgChecker(t *testing.T, path string) *ec.ReadDirArgChecker {
	ino, dev := getInodeInfo(t, path)
	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(fmt.Sprintf("%s/", path))).WithInode(i)
	return ec.NewReadDirArgChecker().WithFile(f)
}

func readdirChecker(t *testing.T, path string) *ec.ProcessFileChecker {
	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	return ec.NewProcessFileChecker("").
		WithProcess(binChecker).
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	// method 1
	if _, err := os.ReadDir(in1); err != nil {
		t.Fatalf("os.ReadDir failed (%s)", err)
	}

	// method 2
	if err := filepath.Walk(in2, func(_ string, _ os.FileInfo, _ error) error {
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

	dirCheckers := []ec.EventChecker{
		readdirChecker(t, in1),
		readdirChecker(t, in2),
		readdirChecker(t, in3),
	}

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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := os.Truncate(oFile, 222); err != nil {
		t.Fatalf("os.Truncate failed (%s)", err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_inode_setattr"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileReadMatchBinary(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
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
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := exec.Command("/usr/bin/cat", oFile).Run(); err != nil {
		t.Logf("failed run  /usr/bin/cat %s: %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix("/usr/bin/cat"))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))
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
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
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
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if _, err := os.ReadFile(oFile); err != nil {
		t.Logf("failed run os.ReadFile(%s): %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testExactFileDelete(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	a := filepath.Join(out, "a")
	createFileInDir(t, a) // create the file before starting FIM

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: a,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	os.Remove(a)          // delete the file that we are monitoring
	createFileInDir(t, a) // create a new file with the same name

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	ino, dev := getInodeInfo(t, a)
	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(genericArgFilenameChecker(a, ino, dev))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileChmod(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	sb, err := os.Stat(oFile)
	if err != nil {
		t.Fatalf("os.Stat failed (%s)", err)
	}

	if err := os.Chmod(oFile, 0666); err != nil {
		t.Fatalf("os.Chmod failed (%s)", err)
	}

	sa, err := os.Stat(oFile)
	if err != nil {
		t.Fatalf("os.Stat failed (%s)", err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	p := ec.NewAttrChangeChecker().WithNew(sm.Full(fmt.Sprintf("%v (%#o)", sa.Mode(), sa.Mode()))).WithOld(sm.Full(fmt.Sprintf("%v (%#o)", sb.Mode(), sb.Mode())))
	a := ec.NewFileAttrChecker().WithPermissions(p)
	c := ec.NewAttrArgChecker().WithFile(f).WithAttr(a)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_CHATTR).
		WithArgs(ec.NewFileArgumentChecker().WithAttrArg(c)).
		WithHook(sm.Full("security_inode_setattr"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileChown(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	var sb syscall.Stat_t
	if err := syscall.Stat(oFile, &sb); err != nil {
		t.Fatalf("syscall.Stat failed (%s)", err)
	}

	if err := os.Chown(oFile, 99, 99); err != nil {
		t.Fatalf("os.Chmod failed (%s)", err)
	}

	var sa syscall.Stat_t
	if err := syscall.Stat(oFile, &sa); err != nil {
		t.Fatalf("syscall.Stat failed (%s)", err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	u := ec.NewAttrChangeChecker().WithNew(sm.Full(fmt.Sprintf("%d", sa.Uid))).WithOld(sm.Full(fmt.Sprintf("%d", sb.Uid)))
	g := ec.NewAttrChangeChecker().WithNew(sm.Full(fmt.Sprintf("%d", sa.Gid))).WithOld(sm.Full(fmt.Sprintf("%d", sb.Gid)))
	a := ec.NewFileAttrChecker().WithUid(u).WithGid(g)
	c := ec.NewAttrArgChecker().WithFile(f).WithAttr(a)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_CHATTR).
		WithArgs(ec.NewFileArgumentChecker().WithAttrArg(c)).
		WithHook(sm.Full("security_inode_setattr"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileReadWriteMultipleSelectors(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
		Selectors: []v1alpha1.FileSelector{
			{
				MatchOperations: []v1alpha1.OperationSelector{
					{
						Operator: "In",
						Values:   []string{"FILE_READ"},
					},
				},
			},
			{
				MatchOperations: []v1alpha1.OperationSelector{
					{
						Operator: "In",
						Values:   []string{"FILE_WRITE"},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if _, err := os.ReadFile(oFile); err != nil {
		t.Logf("failed run os.ReadFile(%s): %s", oFile, err)
	}

	file, err := os.OpenFile(oFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteString("some random test data here"); err != nil {
		t.Logf("failed run file.WriteString(%s): %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	fileReadChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))
	fileWriteChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))
	checker := ec.NewUnorderedEventChecker(fileReadChecker, fileWriteChecker)

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func getExecChecker(t *testing.T, path string) *ec.ProcessFileChecker {
	ino, dev := getInodeInfo(t, path)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(path)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	return ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_EXEC).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_bprm_check"))
}

func testFileExec(gt *testing.T, t *testing.T) {
	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: "/usr/bin/cat",
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := exec.Command("/usr/bin/cat", oFile).Run(); err != nil {
		t.Logf("failed run  /usr/bin/cat %s: %s", oFile, err)
	}

	checker := ec.NewUnorderedEventChecker(getExecChecker(t, "/usr/bin/cat"))

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileExecInterpreter(gt *testing.T, t *testing.T) {
	testBin := testutils.RepoRootPath("contrib/tester-progs/test.sh")

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: "/usr/bin/bash",
				},
			},
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: testBin,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if err := exec.Command(testBin).Run(); err != nil {
		t.Logf("failed run %s: %s", testBin, err)
	}

	checker := ec.NewUnorderedEventChecker(
		getExecChecker(t, "/usr/bin/bash"),
		getExecChecker(t, testBin),
	)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func testFileReadSelectorCapNs(gt *testing.T, t *testing.T) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring with capability and namespace selectors requires at least 5.4.0 kernel version")
	}

	out := filepath.Join(workingDir, "fim_test_outdir")
	createTestDir(t, out)

	oFile := filepath.Join(out, "test1")
	createFileInDir(t, oFile)

	if err := reGenerateFimMaps(&v1alpha1.FileSpec{
		PathsPatterns: []v1alpha1.FilePathPattern{
			{
				Type: "PathPrefix",
				PathPrefix: &v1alpha1.PathPrefixPattern{
					Prefix: out,
				},
			},
		},
		PathsExclude:     []string{},
		Config:           make(map[string]string),
		MonitorHostFiles: true,
		// these tests always run on a vm or on a bare metal host with sudo
		// so they are in the host mnt namespace and with CAP_SYS_ADMIN
		Selectors: []v1alpha1.FileSelector{
			{
				MatchNamespacesOSS: []v1alpha1.NamespaceSelector{
					{
						Namespace: "Mnt",
						Operator:  "In",
						Values: []string{
							"host_ns",
						},
					},
				},
				MatchCapabilitiesOSS: []v1alpha1.CapabilitiesSelector{
					{
						Type:     "Effective",
						Operator: "In",
						Values: []string{
							"CAP_SYS_ADMIN",
						},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("ReGenerateFimMaps failed with %s", err)
	}

	if _, err := os.ReadFile(oFile); err != nil {
		t.Logf("failed run os.ReadFile(%s): %s", oFile, err)
	}

	ino, dev := getInodeInfo(t, oFile)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(oFile)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	fileChecker := ec.NewProcessFileChecker("").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))
	checker := ec.NewUnorderedEventChecker(fileChecker)

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(gt, err)
}

func TestFileOps(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	specFname := createSpecFile(t, "/sample/file") // this file does not exist -- we only need to initialize all fim progs and maps
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	// Can't use observer.WithMyPid() here because we are also checking events from
	// a spawned container here.
	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFname, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	for name, fn := range map[string]func(*testing.T, *testing.T){
		"readv":              testFileReadV,
		"preadv":             testFilePReadV,
		"preadv2":            testFilePReadV2,
		"pread64":            testFilePRead64,
		"write":              testFileWrite,
		"writev":             testFileWriteV,
		"pwritev":            testFilePWriteV,
		"pwritev2":           testFilePWriteV2,
		"pwrite64":           testFilePWrite64,
		"mmapreadpopulate":   testFileMmapReadPopulate,
		"mmapwritepopulate":  testFileMmapWritePopulate,
		"mmapread":           testFileMmapRead,
		"mmapreadwrite":      testFileMmapReadWrite,
		"mmapwrite":          testFileMmapWrite,
		"mmapwriteread":      testFileMmapWriteRead,
		"sendfile":           testSendfile,
		"copyfilerange":      testCopyFileRange,
		"splice":             testFileSplice,
		"fallocate":          testFileFallocate,
		"dlopen":             testDlopenRead,
		"aiopread":           testFileAioPRead,
		"aiopreadv":          testFileAioPReadV,
		"aiopwrite":          testFileAioPWrite,
		"aiopwritev":         testFileAioPWriteV,
		"cpiouring":          testFileCpIouring,
		"catiouring":         testFileCatIouring,
		"writeiouring":       testFileWriteIouring,
		"polliouring":        testFilePollingIouring,
		"create":             testFileCreate,
		"delete":             testFileDelete,
		"rename1":            testFileRename1,
		"rename2":            testFileRename2,
		"rename3":            testFileRename3,
		"rename4":            testFileRename4,
		"rename5":            testFileRename5,
		"rename6":            testFileRename6,
		"rename7":            testFileRename7,
		"rename8":            testFileRename8,
		"rename9":            testFileRename9,
		"rename10":           testFileRename10,
		"rename11":           testFileRename11,
		"rename12":           testFileRename12,
		"rename13":           testFileRename13,
		"rename14":           testFileRename14,
		"mkdir":              testFileMkdir,
		"rmdir":              testFileRmdir,
		"readdir":            testFileReadDir,
		"truncate":           testFileTruncate,
		"fileexec":           testFileExec,
		"fileexecint":        testFileExecInterpreter,
		"readmatchbinary":    testFileReadMatchBinary,
		"readmatchoperation": testFileReadMatchOperation,
		"exactfiledelete":    testExactFileDelete,
		"chmod":              testFileChmod,
		"chown":              testFileChown,
		"multipleselectors":  testFileReadWriteMultipleSelectors,
		"selectorcapns":      testFileReadSelectorCapNs,
	} {
		if !t.Run(name, func(lt *testing.T) { fn(t, lt) }) {
			break // stop on first failure
		}
	}
}

func TestFileReadPolicy(t *testing.T) {
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	enterprisepolicytest.DoObserverTest(t, "file-read", nil)
}

func TestFileUserDefinedMapSizes(t *testing.T) {
	filePasswd := "/etc/passwd"
	specFile := newSpecFile(t, filePasswd, "file_monitoring_config.yaml.tmpl")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	pol.ResetFIMTracingPolicies()
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command("/bin/cat", filePasswd).Run(); err != nil {
		t.Fatalf("failed to run /bin/cat %s: err %s", filePasswd, err)
	}

	inodeMapPath := program.PolicyMapPath(bpf.MapPrefixPath(), "file-monitoring", "hash_map_inode_alloc")
	inodeHandle, err := ebpf.LoadPinnedMap(inodeMapPath, nil)
	if err != nil {
		t.Fatalf("cannot open pinned map %s", inodeMapPath)
	}
	defer inodeHandle.Close()
	// 4096 is the value of watchedInodeMapMaxiumSize in testdata/specs/file_monitoring_config.yaml.tmpl
	assert.Equal(t, uint32(4096), inodeHandle.MaxEntries())

	ino, dev := getInodeInfo(t, filePasswd)
	o := ec.NewFileOperationListMatcher().
		WithOperator(lm.Ordered).
		WithValues(
			ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_POST),
		)

	fileExecChecker := ec.NewProcessFileChecker("TestFileUserDefinedMapSizes").
		WithAction(tetragon.FileAction_FILE_READ).
		WithArgs(genericArgFilenameChecker(filePasswd, ino, dev)).
		WithOperation(o)
	checker := ec.NewUnorderedEventChecker(fileExecChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestFileRenameDirSuffix(t *testing.T) {
	if !bpf.HasProgramLargeSize() {
		t.Skip("Suffix match in FIM requires support for large programs")
	}

	outTest := filepath.Join(workingDir, t.Name())
	createTestDir(t, outTest)

	outDst := filepath.Join(outTest, "a")
	createTestDir(t, outDst)

	outSrc := filepath.Join(outTest, "b")
	createTestDir(t, outSrc)

	files := []string{"file.a", "file.b", "file.c", "file.d"}
	for _, file := range files {
		oFile := filepath.Join(outSrc, file)
		createFileInDir(t, oFile)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	base := base.GetInitialSensorTest(t)
	specFile := newSpecFile(t, fmt.Sprintf("%s/", outDst), "file_monitoring_suffix.yaml.tmpl")
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := os.Rename(outSrc, fmt.Sprintf("%s/b", outDst)); err != nil {
		t.Errorf("os.Rename failed (%s)", err)
	}

	time.Sleep(renameDelay * time.Millisecond) // should be enough to handle rename in user-space

	outRead := filepath.Join(outTest, "a", "b")
	for _, file := range files {
		fileRead(t, filepath.Join(outRead, file))
	}

	fileCheckers := []ec.EventChecker{
		renameRenameChecker(t, outSrc, fmt.Sprintf("%s/b", outDst), "MOVE_INTERNALLY", "SRC_DIRECTORY", "DST_NOT_EXISTS"),
		renameOpenChecker(t, filepath.Join(outRead, files[0])),
		renameReadChecker(t, filepath.Join(outRead, files[0])),
		renameOpenChecker(t, filepath.Join(outRead, files[1])),
		renameReadChecker(t, filepath.Join(outRead, files[1])),
	}

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// This test represents the issue reported by Cure53 in https://github.com/isovalent/hubble-fgs/issues/3289
func TestFileLinkOnTmpFile(t *testing.T) {
	outTest := filepath.Join(workingDir, t.Name())
	createTestDir(t, outTest)

	outDst := filepath.Join(outTest, "a")
	createTestDir(t, outDst)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	base := base.GetInitialSensorTest(t)

	specFile := newSpecFile(t, fmt.Sprintf("%s/", outDst), "file_monitoring_config.yaml.tmpl")
	fm.ScannerFifoPath = path.Join(t.TempDir(), fm.ScannerFifoName)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, specFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithLib error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	t.Cleanup(func() {
		TerminateFsScanner()
		pol.ResetFIMTracingPolicies()
	})
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// create a temporary file in a directory that we don't monitor
	fd, err := unix.Open(outTest, unix.O_TMPFILE|unix.O_RDWR, unix.S_IRUSR|unix.S_IWUSR)
	if err != nil {
		t.Errorf("unix.Open failed (%s)", err)
	}

	// get the inode number of the temporary file
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err != nil {
		t.Errorf("unix.Fstat failed (%s)", err)
	}

	// create a link to the temporary file in a directory that we monitor
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	linkPath := filepath.Join(outDst, "tmp_link.txt")
	err = unix.Linkat(unix.AT_FDCWD, path, unix.AT_FDCWD, linkPath, unix.AT_SYMLINK_FOLLOW)
	if err != nil {
		t.Errorf("unix.Linkat failed (%s)", err)
	}

	err = unix.Close(fd)
	if err != nil {
		t.Errorf("unix.Close failed (%s)", err)
	}

	file, err := os.OpenFile(linkPath, os.O_RDWR, 0)
	if err != nil {
		t.Errorf("os.OpenFile failed (%s)", err)
	}
	defer file.Close()

	// write to link
	if _, err := file.WriteString("some random test data here"); err != nil {
		t.Errorf("failed run file.WriteString(%s): %s", linkPath, err)
	}

	ino, dev := getInodeInfo(t, linkPath)

	// the link inode number should be the same as the temporary file
	assert.Equal(t, stat.Ino, ino)

	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(linkPath)).WithInode(i)
	c := ec.NewGenericFileArgChecker().WithFile(f)

	fl := ec.NewStringListMatcher().
		WithOperator(lm.Unordered).
		WithValues(
			sm.Full("O_RDWR"),
		)
	of := ec.NewFileDetailsChecker().WithStr(sm.Full(linkPath)).WithInode(i).WithOpenFlags(fl)
	oc := ec.NewGenericFileArgChecker().WithFile(of)

	execPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable name: %s", err)
	}
	binChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(execPath))

	openChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_OPEN).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(oc)).
		WithHook(sm.Full("security_file_open"))

	linkChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_LINK).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_inode_link"))

	writeChecker := ec.NewProcessFileChecker("").
		WithProcess(binChecker).
		WithAction(tetragon.FileAction_FILE_WRITE).
		WithArgs(ec.NewFileArgumentChecker().WithGenericArg(c)).
		WithHook(sm.Full("security_file_permission"))

	fileCheckers := []ec.EventChecker{
		openChecker,
		linkChecker,
		writeChecker,
	}

	checker := ec.NewUnorderedEventChecker(fileCheckers...)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestBPFFilesExist(t *testing.T) {
	for _, hks := range [][]FimHook{{FimPathBasedGetnameHook}, {FimPathBasedGetnameFlagsHook}, FimPathBasedArchHooks[:], FimPathBasedHooks[:], FimPathBasedTailCallHooks[:], FimPathBasedHooksExec[:], FimPathBasedHooksExecDigests[:], FimHooksObserve[:], {FimHooksObserveExec}, FimHooksFmodRet[:], {FimHooksFmodRetExec}, FimHooksLsm[:], {FimHooksLsmExec}, FimHooksLsmExecDigests[:], FimIoUringHooks[:], FimIoUringSingleHooks[:], FimHooksFileCreate[:], FimHooksFileCreate418[:]} {
		for _, hk := range hks {
			for _, of := range hk.prog {
				objFile := filepath.Join(runner.Conf().TetragonLib, of.progName)
				assert.True(t, fileExists(t, objFile), "object file %s does not exist", objFile)
			}
		}
	}
}
