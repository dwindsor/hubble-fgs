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
// sudo ./go-tests/file.test --bpf-lib ./bpf/objs/ -test.run TestFileSuffixPattern

//go:build sudo_tests

package file

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	// NB: we need to load these two so that the policy handlers are loaded
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
	ossTestUtils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/file"
	v1api "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFileSuffixPattern(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	if !kernels.MinKernelVersion("5.4.0") {
		t.Skip("File monitoring patterns requires at least 5.4.0 kernel version")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(16384); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-patterns",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "FilePrefixSuffix",
						FilePrefixSuffix: &v1alpha1.FilePrefixSuffixPattern{
							Prefix: testDir,
							Suffix: ".txt",
						},
					},
					{
						Type: "FilePrefixSuffix",
						FilePrefixSuffix: &v1alpha1.FilePrefixSuffixPattern{
							Prefix: testDir,
							Suffix: ".sh",
						},
					},
					{
						Type: "FileExactMatch",
						FileExactMatch: &v1alpha1.FileExactMatchPattern{
							Path: filepath.Join(testDir, "aaa"),
						},
					},
				},
				MonitorHostFiles: true,
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	execFn := func(bin string, args ...string) int {
		cmd := exec.Command(bin, args...)
		err := cmd.Start()
		assert.NoError(t, err)
		pid := cmd.Process.Pid
		err = cmd.Wait()
		assert.NoError(t, err)
		return pid
	}

	executedEvents := []string{}
	ops := func() {
		// (1) check the prefix-suffix patterns
		path := filepath.Join(testDir, "a.txt")
		pid := execFn("/usr/bin/touch", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_CREATE", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))

		path = filepath.Join(testDir, "a.go")
		execFn("/usr/bin/touch", path) // no event for that

		path = filepath.Join(testDir, "a.sh")
		pid = execFn("/usr/bin/touch", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_CREATE", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))

		path = filepath.Join(testDir, "dada")
		execFn("/usr/bin/touch", path) // no event for that

		path = filepath.Join(testDir, "a")
		execFn("/usr/bin/mkdir", path) // no event for that

		path = filepath.Join(testDir, "a", "a.txt")
		pid = execFn("/usr/bin/touch", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_CREATE", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))

		path = filepath.Join(testDir, "a", "a.go")
		execFn("/usr/bin/touch", path) // no event for that

		path = filepath.Join(testDir, "a", "a.sh")
		pid = execFn("/usr/bin/touch", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_CREATE", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))

		path = filepath.Join(testDir, "a.txt")
		pid = execFn("/usr/bin/cat", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_READ", path))

		path = filepath.Join(testDir, "a.go")
		execFn("/usr/bin/cat", path) // no event for that

		path = filepath.Join(testDir, "a.sh")
		pid = execFn("/usr/bin/cat", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_READ", path))

		srcPath := filepath.Join(testDir, "a.sh")
		dstPath := filepath.Join(testDir, "a.cc")
		pid = execFn("/usr/bin/mv", srcPath, dstPath)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s|%s]", pid, "FILE_RENAME", srcPath, dstPath))

		path = filepath.Join(testDir, "a.cc")
		execFn("/usr/bin/cat", path) // no event for that

		srcPath = filepath.Join(testDir, "a.cc")
		dstPath = filepath.Join(testDir, "a.sh")
		pid = execFn("/usr/bin/mv", srcPath, dstPath)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s|%s]", pid, "FILE_RENAME", srcPath, dstPath))

		path = filepath.Join(testDir, "a.sh")
		pid = execFn("/usr/bin/cat", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_READ", path))

		path = filepath.Join(testDir, "a")
		pid = execFn("/usr/bin/rm", filepath.Join(path, "a.sh"), filepath.Join(path, "a.txt"))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_DELETE", filepath.Join(path, "a.sh")))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_DELETE", filepath.Join(path, "a.txt")))

		path = filepath.Join(testDir, "a.txt")
		pid = execFn("/usr/bin/rm", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_DELETE", path))

		path = filepath.Join(testDir, "a.go")
		execFn("/usr/bin/rm", path) // no event for that

		path = filepath.Join(testDir, "a.sh")
		pid = execFn("/usr/bin/rm", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_DELETE", path))

		path = filepath.Join(testDir, "dada")
		execFn("/usr/bin/rm", path) // no event for that

		// (2) check the exact match
		path = filepath.Join(testDir, "aaa")
		pid = execFn("/usr/bin/touch", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_CREATE", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))

		path = filepath.Join(testDir, "aa")
		execFn("/usr/bin/touch", path) // no event for that

		path = filepath.Join(testDir, "aaaa")
		execFn("/usr/bin/touch", path) // no event for that

		path = filepath.Join(testDir, "aaa")
		pid = execFn("/usr/bin/cat", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_OPEN", path))
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_READ", path))

		path = filepath.Join(testDir, "aa")
		execFn("/usr/bin/cat", path) // no event for that

		path = filepath.Join(testDir, "aaaa")
		execFn("/usr/bin/cat", path) // no event for that

		path = filepath.Join(testDir, "aaa")
		pid = execFn("/usr/bin/rm", path)
		executedEvents = append(executedEvents, fmt.Sprintf("[%d|%s|%s]", pid, "FILE_DELETE", path))

		path = filepath.Join(testDir, "aa")
		execFn("/usr/bin/rm", path) // no event for that

		path = filepath.Join(testDir, "aaaa")
		execFn("/usr/bin/rm", path) // no event for that
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	capturedEvents := []string{}
	for _, ev := range events {
		if file, ok := ev.(*grpc.MsgFileEventUnix); ok {
			capturedEvents = append(capturedEvents, fmt.Sprintf("[%d|%s|%s]", file.Msg.ProcessKey.Pid, tetragon.FileAction(file.Msg.Action), file.Path))
		} else if file, ok := ev.(*grpc.MsgFileRenameEventUnix); ok {
			capturedEvents = append(capturedEvents, fmt.Sprintf("[%d|%s|%s|%s]", file.Msg.ProcessKey.Pid, tetragon.FileAction(file.Msg.Action), file.Src.Path, file.Dst.Path))
		}
	}

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	assert.Equal(t, len(executedEvents), len(capturedEvents), "Got a different number of events compared to what expected")
	if len(executedEvents) != len(capturedEvents) { // different number of events, print everything
		execEvents := "Executed:"
		for _, e := range executedEvents {
			execEvents += ("\n" + e)
		}
		t.Log(execEvents)

		captEvents := "Captured:"
		for _, e := range capturedEvents {
			captEvents += ("\n" + e)
		}
		t.Log(captEvents)
	} else { // same number of events, compare all of them to be the same
		// sort both slices to avoid flakes due to out-of-order event delivery
		sort.Strings(executedEvents)
		sort.Strings(capturedEvents)

		for i := 0; i < len(capturedEvents); i++ {
			assert.Equal(t, executedEvents[i], capturedEvents[i], "Got a different event compared to what expected")
		}
	}
}

func TestFileFsTypeMatch(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
		t.Skip("File monitoring patterns with FileSystemType type requires fmod_ret and lsm programs, bpf_loop and bpf_for_each_map_elem helpers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(16384); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-fs-type",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "FileSystemType",
						FileSystemType: &v1alpha1.FileSystemTypePattern{
							Names: []string{
								"proc",
								"sysfs",
							},
						},
					},
				},
				MonitorHostFiles: true,
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	execFn := func(bin string, args ...string) {
		cmd := exec.Command(bin, args...)
		assert.NoError(t, cmd.Run())
	}

	ops := func() {
		a := filepath.Join(testDir, "a.txt")
		b := filepath.Join(testDir, "b.txt")

		// local file system (possibly ext4, xfs, or btrfs)
		execFn("/usr/bin/touch", a)
		execFn("/usr/bin/cat", a)
		execFn("/usr/bin/mv", a, b)
		execFn("/usr/bin/rm", b)

		// proc file system
		execFn("/usr/bin/cat", "/proc/sys/vm/oom_dump_tasks")
		execFn("/usr/bin/ls", "/proc/")

		// tmpfs
		execFn("/usr/bin/touch", "/tmp/data.txt")

		// sysfs
		execFn("/usr/bin/ls", "/sys/")
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	// make sure that all events are from "proc" and "sysfs" file systems
	procEvents := 0
	sysfsEvents := 0
	for _, ev := range events {
		if file, ok := ev.(*grpc.MsgFileEventUnix); ok {
			if file.Fs.SName != "proc" && file.Fs.SName != "sysfs" {
				assert.NoError(t, fmt.Errorf("file operation to %s which is in %s file system", file.Path, file.Fs.SName))
			}
			if file.Fs.SName == "proc" {
				procEvents++
			}
			if file.Fs.SName == "sysfs" {
				sysfsEvents++
			}
		} else if file, ok := ev.(*grpc.MsgFileRenameEventUnix); ok {
			if (file.Src.Fs.SName != "proc" && file.Dst.Fs.SName != "proc") && (file.Src.Fs.SName != "sysfs" && file.Dst.Fs.SName != "sysfs") {
				assert.NoError(t, fmt.Errorf("file operation (rename) from %s which is in %s file system to %s which is in %s file system", file.Src.Path, file.Src.Fs.SName, file.Dst.Path, file.Dst.Fs.SName))
			}
		}
	}

	// make sure that we also get some events from proc and sysfs
	assert.Greater(t, procEvents, 0, "we expect to have at least one event from proc")
	assert.Greater(t, sysfsEvents, 0, "we expect to have at least one event from sysfs")
}

func TestFileGlobMatch(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
		t.Skip("File monitoring patterns with AllFileOps type requires fmod_ret and lsm programs, bpf_loop and bpf_for_each_map_elem helpers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(16384); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-glob",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "AllFileOps",
					},
				},
				MonitorHostFiles: true,
				Selectors: []v1alpha1.FileSelector{
					{
						MatchFilename: []v1alpha1.FilePathGlobSelector{
							{
								Operator: "InPattern",
								Values: []v1alpha1.GlobPattern{
									"*.c",
									"/*/?.txt",
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	execFn := func(bin string, args ...string) {
		cmd := exec.Command(bin, args...)
		assert.NoError(t, cmd.Run())
	}

	ops := func() {
		a := filepath.Join(testDir, "a.txt")  // match on "/*/?.txt"
		b := filepath.Join(testDir, "bb.txt") // does not match
		c := filepath.Join(testDir, "c.c")    // match on "*.c"
		d := filepath.Join(testDir, "d.go")   // does not match
		e := filepath.Join(testDir, "e.dat")  // does not match

		execFn("/usr/bin/touch", a) // match
		execFn("/usr/bin/touch", b) // no match
		execFn("/usr/bin/touch", c) // match

		execFn("/usr/bin/mv", c, d) // src match
		execFn("/usr/bin/mv", d, e) // nothing match
		execFn("/usr/bin/mv", e, c) // dst match

		execFn("/usr/bin/ln", c, e)       // src match
		execFn("/usr/bin/ln", "-s", c, d) // src match

		execFn("/usr/bin/rm", a) // match
		execFn("/usr/bin/rm", b) // no match
		execFn("/usr/bin/rm", c) // match
		execFn("/usr/bin/rm", d) // no match
		execFn("/usr/bin/rm", e) // no match
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	assert.Greater(t, len(events), 0, "we expect to have some events")

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	capturedEvents := 0
	capturedLinkEvents := 0
	capturedSymlinkEvents := 0
	for _, ev := range events {
		if _, ok := ev.(*grpc.MsgFileEventUnix); ok {
			capturedEvents++
		} else if _, ok := ev.(*grpc.MsgFileLinkEventUnix); ok {
			capturedLinkEvents++
		} else if _, ok := ev.(*grpc.MsgFileSymlinkEventUnix); ok {
			capturedSymlinkEvents++
		} else if _, ok := ev.(*grpc.MsgFileRenameEventUnix); ok {
			capturedEvents++
		}
	}

	assert.Equal(t, capturedEvents, 6, "we expect to have 6 events")
	assert.Equal(t, capturedLinkEvents, 1, "we expect to have 1 link event")
	assert.Equal(t, capturedSymlinkEvents, 1, "we expect to have 1 symlink event")
}

func TestFileDigestMatch(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	_, imaSupport := probeImaEnabled()
	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) || (imaSupport != nil) {
		t.Skip("File monitoring digests type requires fmod_ret and lsm programs, bpf_loop and bpf_for_each_map_elem helpers and IMA to be enabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(16384); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-path-digest",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				Config: map[string]string{
					"enableExecDigests": "true",
				},
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "AllFileOps",
					},
				},
				MonitorHostFiles: true,
				Selectors: []v1alpha1.FileSelector{
					{
						MatchOperations: []v1alpha1.OperationSelector{
							{
								Operator: "In",
								Values: []string{
									"FILE_EXEC",
								},
							},
						},
						MatchFilename: []v1alpha1.FilePathGlobSelector{
							{
								Operator: "InFileWithDigest",
								Values: []v1alpha1.GlobPattern{
									"/usr/bin/touch",
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	execFn := func(bin string, args ...string) {
		cmd := exec.Command(bin, args...)
		assert.NoError(t, cmd.Run())
	}

	ops := func() {
		a := filepath.Join(testDir, "a.txt")
		execFn("/usr/bin/touch", a) // match
		execFn("/usr/bin/rm", a)    // no-match
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	assert.Greater(t, len(events), 0, "we expect to have some events")

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	capturedEvents := 0
	eventPath := ""
	for _, ev := range events {
		if e, ok := ev.(*grpc.MsgFileEventUnix); ok {
			eventPath = e.Path
			capturedEvents++
		}
	}

	assert.Equal(t, capturedEvents, 1, "we expect to have 1 event")
	assert.Equal(t, eventPath, "/usr/bin/touch", "we expect the event to be for /usr/bin/touch")
}

func TestMatchBinariesFollowChildren(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("failed to find 'sh' exec: %v", err)
	}
	tmpShPath, err := ossTestUtils.CopyFileToTmp(shPath)
	if err != nil {
		t.Fatalf("failed to copy 'sh' exec: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(tmpShPath)
	})

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	tmpFile := filepath.Join(testDir, "a.txt")
	createFileInDir(t, tmpFile)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-matchbinaries",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "PathPrefix",
						PathPrefix: &v1alpha1.PathPrefixPattern{
							Prefix: testDir,
						},
					},
				},
				MonitorHostFiles: true,
				Selectors: []v1alpha1.FileSelector{
					{
						MatchBinaries: []v1alpha1.BinarySelector{{
							Operator: "In",
							Values: []string{
								tmpShPath,
							},
							FollowChildren: true,
						}},
					},
				},
			},
		},
	}

	err = sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	var numFileOpen, numFileRead, otherFileEvents int
	eventFn := func(ev notify.Message) error {
		if file, ok := ev.(*grpc.MsgFileEventUnix); ok {
			if file.Path != tmpFile {
				otherFileEvents++
				return nil
			}

			if tetragon.FileAction(file.Msg.Action) == tetragon.FileAction_FILE_READ {
				numFileRead++
			} else if tetragon.FileAction(file.Msg.Action) == tetragon.FileAction_FILE_OPEN {
				numFileOpen++
			}
		}
		return nil
	}

	getPread64Bin := testutils.RepoRootPath("contrib/tester-progs/read_write/pread64")
	ops := func() {
		cmd := exec.Command(tmpShPath, "-c", fmt.Sprintf("%s $0", getPread64Bin), tmpFile)
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}
	}

	perfring.RunTest(t, ctx, ops, eventFn)

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	require.Equal(t, 1, numFileOpen)     // we expect one open call
	require.Equal(t, 1, numFileRead)     // we expect one read call
	require.Equal(t, 0, otherFileEvents) // we don't expect any other FIM events
}

func TestMatchExecAttributes(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
		t.Skip("File monitoring with AllFileOps type requires fmod_ret and lsm programs, bpf_loop and bpf_for_each_map_elem helpers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-matchexecattr",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "AllFileOps",
					},
				},
				MonitorHostFiles: true,
				Selectors: []v1alpha1.FileSelector{
					{
						MatchOperations: []v1alpha1.OperationSelector{
							{
								Operator: "In",
								Values: []string{
									"FILE_EXEC",
								},
							},
						},
						MatchExecAttributes: []v1alpha1.FileExecAttributesSelector{
							{
								IsFromMemfd:  "True",
								IsUpperLayer: "Any",
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	var numFileExec, numFileOthers int
	eventFn := func(ev notify.Message) error {
		if file, ok := ev.(*grpc.MsgFileEventUnix); ok {
			if tetragon.FileAction(file.Msg.Action) == tetragon.FileAction_FILE_EXEC {
				numFileExec++
			} else {
				numFileOthers++
			}
		}
		return nil
	}

	memfdExecBin := testutils.RepoRootPath("contrib/tester-progs/memfd_exec")
	ops := func() {
		cmd := exec.Command(memfdExecBin)
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}
	}

	perfring.RunTest(t, ctx, ops, eventFn)

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	require.Equal(t, 1, numFileExec)   // we expect one exec event
	require.Equal(t, 0, numFileOthers) // we don't expect any other FIM events
}

type OpenRawTestCase struct {
	Path           string
	TpName         string
	Hook           uint32
	Retval         int32
	IsRelativePath int32
}

func TestMatchOpenrawOps(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger())

	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
		t.Skip("File monitoring with AllFileOps type requires fmod_ret and lsm programs, bpf_loop and bpf_for_each_map_elem helpers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	eeOption.Config.FimFifoLocalPath = fm.LocalScannerFifoPath
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	testDir := filepath.Join(workingDir, fmt.Sprintf("fim_test_dir_%s", filepath.Base(t.Name())))
	createTestDir(t, testDir)

	fileTracingPolicy := tracingpolicy.GenericTracingPolicy{
		Metadata: v1api.ObjectMeta{
			Name: "file-monitoring-openraw",
		},
		Spec: v1alpha1.TracingPolicySpec{
			FileMonitoring: v1alpha1.FileSpec{
				PathsPatterns: []v1alpha1.FilePathPattern{
					{
						Type: "AllFileOps",
					},
				},
				MonitorHostFiles: true,
				Selectors: []v1alpha1.FileSelector{
					{
						MatchOperations: []v1alpha1.OperationSelector{
							{
								Operator: "In",
								Values: []string{
									"FILE_OPENRAW",
								},
							},
						},
						MatchFilename: []v1alpha1.FilePathGlobSelector{
							{
								Operator: "InPattern",
								Values: []v1alpha1.GlobPattern{
									"*passwd*",
									"*something_wrong*",
								},
							},
						},
						MatchOpenFlags: []v1alpha1.FileOpenFlagsTypeSelector{
							{
								Operator: "In",
								Values: []v1alpha1.OpenFlagSelectorValue{
									"O_RDWR",
								},
							},
							{
								Operator: "In",
								Values: []v1alpha1.OpenFlagSelectorValue{
									"O_RDONLY",
								},
							},
						},
					},
				},
			},
		},
	}

	err := sm.Manager.AddTracingPolicy(ctx, &fileTracingPolicy)
	assert.NoError(t, err)

	t.Cleanup(func() {
		TerminateFsScanner()
		os.RemoveAll(option.Config.BpfDir)
	})

	expectedEvents := map[OpenRawTestCase]int{
		OpenRawTestCase{
			Path:           "/etc/passwd",
			TpName:         "file-monitoring-openraw",
			Hook:           41, // hook_io_openat2
			Retval:         0,
			IsRelativePath: 0,
		}: 0,
		OpenRawTestCase{
			Path:           "./something_wrong.txt",
			TpName:         "file-monitoring-openraw",
			Hook:           41, // hook_io_openat2
			Retval:         int32(unix.ENOENT),
			IsRelativePath: 1,
		}: 0,
		OpenRawTestCase{
			Path:           "/etc/passwd",
			TpName:         "file-monitoring-openraw",
			Hook:           44, // hook_sys_openat
			Retval:         0,
			IsRelativePath: 0,
		}: 0,
		OpenRawTestCase{
			Path:           "./something_wrong.txt",
			TpName:         "file-monitoring-openraw",
			Hook:           44, // hook_sys_openat
			Retval:         int32(unix.ENOENT),
			IsRelativePath: 1,
		}: 0,
	}

	// var numFileExec int
	eventFn := func(ev notify.Message) error {
		if file, ok := ev.(*grpc.MsgFileOpenrawEventUnix); ok {
			e := OpenRawTestCase{
				Path:           file.Path,
				TpName:         file.TpName,
				Hook:           file.Msg.Hook,
				Retval:         file.Retval,
				IsRelativePath: file.Msg.IsRelativePath,
			}

			if _, ok := expectedEvents[e]; ok {
				expectedEvents[e]++
			}
		}
		return nil
	}

	openIoUringBin := testutils.RepoRootPath("contrib/tester-progs/io_uring/open_liburing")
	ops := func() {
		cmd := exec.Command(openIoUringBin, "/etc/passwd")
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}

		cmd = exec.Command(openIoUringBin, "./something_wrong.txt")
		if err := cmd.Run(); err == nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}

		if fd, err := syscall.Openat(unix.AT_FDCWD, "/etc/passwd", unix.O_RDONLY, 0); err != nil {
			t.Fatalf("failed to run openat syscall: %v", err)
		} else {
			syscall.Close(fd)
		}

		if fd, err := syscall.Openat(unix.AT_FDCWD, "./something_wrong.txt", unix.O_RDONLY, 0); err == nil {
			syscall.Close(fd)
			t.Fatalf("succeed openat syscall that should fail")
		}
	}

	perfring.RunTest(t, ctx, ops, eventFn)

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	for ev, cnt := range expectedEvents {
		require.Equal(t, 1, cnt, "all events should appear exactly once: %s", ev)
	}
}
