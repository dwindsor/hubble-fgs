// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/testutils/policytestconfig"
)

func genericArgFilenameChecker(fileName string, ino uint64, dev string) *ec.FileArgumentChecker {
	s := ec.NewFileSystemChecker().WithDev(sm.Full(dev))
	i := ec.NewInodeChecker().WithNumber(ino).WithFs(s)
	l := ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE)
	f := ec.NewFileDetailsChecker().WithStr(sm.Full(fileName)).WithInode(i).WithLocation(l)
	c := ec.NewGenericFileArgChecker().WithFile(f)
	return ec.NewFileArgumentChecker().WithGenericArg(c)
}

var _ = policytest.NewBuilder("file-read").
	WithLabels("file").
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-read"
spec:
  file:
    file_paths_patterns:
    - type: PathPrefix
      path_prefix:
        prefix: {{ tempFile "file-read" }}
    monitorHostFiles: true
`).
	AddScenario(func(conf *policytest.Conf) *policytest.Scenario {
		triggerPath := policytestconfig.EnterpriseTestBinary("read_write/read")
		filePath := conf.TempFileMust("file-read")
		if err := os.WriteFile(filePath, []byte("some random test data here"), 0600); err != nil {
			panic(err)
		}
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			panic(err)
		}
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok {
			panic("file stat is not syscall.Stat_t")
		}
		device := fmt.Sprintf("%d:%d", unix.Major(stat.Dev), unix.Minor(stat.Dev))
		fileChecker := genericArgFilenameChecker(filePath, stat.Ino, device)
		processChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(triggerPath)))

		return &policytest.Scenario{
			Name:    "read a monitored host file",
			Trigger: policytest.NewCmdTrigger(triggerPath, filePath),
			EventChecker: ec.NewUnorderedEventChecker(
				ec.NewProcessFileChecker("fileOpen").
					WithProcess(processChecker).
					WithAction(tetragon.FileAction_FILE_OPEN).
					WithArgs(fileChecker),
				ec.NewProcessFileChecker("fileRead").
					WithProcess(processChecker).
					WithAction(tetragon.FileAction_FILE_READ).
					WithArgs(fileChecker),
			),
		}
	}).
	RegisterAtInit()
