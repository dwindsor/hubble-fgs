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

package file

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	// NB: we need to load these two so that the policy handlers are loaded
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"

	ossTestUtils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/file"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	v1api "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFileSuffixPattern(t *testing.T) {
	ossTestUtils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

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
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

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
	ossTestUtils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

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
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

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
	ossTestUtils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

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
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tus.GetTestSensorManager(ctx, t)

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

		execFn("/usr/bin/rm", a) // match
		execFn("/usr/bin/rm", b) // no match
		execFn("/usr/bin/rm", c) // match
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	assert.Greater(t, len(events), 0, "we expect to have some events")

	err = sm.Manager.DeleteTracingPolicy(ctx, fileTracingPolicy.Metadata.Name, "")
	assert.NoError(t, err)

	capturedEvents := 0
	for _, ev := range events {
		if _, ok := ev.(*grpc.MsgFileEventUnix); ok {
			capturedEvents++
		} else if _, ok := ev.(*grpc.MsgFileRenameEventUnix); ok {
			capturedEvents++
		}
	}

	assert.Equal(t, capturedEvents, 6, "we expect to have 6 events")
}
