//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build sudo_tests

package exec

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/assert"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func killAndWaitCommand(t *testing.T, cmd *exec.Cmd) {
	if cmd != nil {
		if cmd.Process != nil {
			cmd.Process.Kill()
		} else {
			t.Logf("Command %q process disappeared, skipping kill", cmd.Args[0])
		}
		_ = cmd.Wait()
	}
}

func testAncestorsN(t *testing.T, numAncestors int) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/proctree")
	sleepBin := "/bin/sleep"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	testBinCheckers := make([]*ec.ProcessChecker, numAncestors+1)
	testBinCheckers[0] = ec.NewProcessChecker().
		WithBinary(sm.Suffix(testBin)).
		WithArguments(sm.Full(fmt.Sprintf("%d", numAncestors)))
	for a := 1; a < numAncestors+1; a++ {
		testBinCheckers[a] = ec.NewProcessChecker().
			WithBinary(sm.Suffix(testBin)).
			WithArguments(sm.Full(fmt.Sprintf("%d", a-numAncestors)))
	}

	testSleepChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(sleepBin)).
		WithArguments(sm.Full("1"))

	checkers := make([]ec.EventChecker, numAncestors+3)
	checkers[0] = ec.NewProcessExecChecker("selfExec").
		WithProcess(selfChecker).
		WithParent(ec.NewProcessChecker())
	checkers[1] = ec.NewProcessExecChecker("testBin").
		WithProcess(testBinCheckers[0]).
		WithParent(selfChecker)
	for a := 2; a < numAncestors+2; a++ {
		checkers[a] = ec.NewProcessExecChecker(fmt.Sprintf("testBin%d", numAncestors+1-a)).
			WithProcess(testBinCheckers[a-1]).
			WithParent(testBinCheckers[a-2])
	}
	ancestors := make([]*ec.ProcessChecker, numAncestors)
	for a := 0; a < numAncestors; a++ {
		ancestors[a] = testBinCheckers[a]
	}
	checkers[numAncestors+2] = ec.NewProcessExecChecker("sleepBin").
		WithProcess(testSleepChecker).
		WithParent(testBinCheckers[numAncestors]).
		WithAncestors(ec.NewProcessListMatcher().
			WithValues(ancestors...))

	checker := ec.NewUnorderedEventChecker(checkers...)

	// Enable process ancestors
	oldEnableProcessAncestorsValue := option.Config.EnableProcessAncestors
	option.Config.EnableProcessAncestors = true
	t.Cleanup(func() {
		option.Config.EnableProcessAncestors = oldEnableProcessAncestorsValue
	})

	// Use short process cache GC interval to speed up test
	obs, err := enterpriseoth.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithProcCacheGCInterval(500*time.Millisecond))
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmd := exec.Command(testBin, fmt.Sprintf("%d", numAncestors))
	assert.NoError(t, cmd.Start())
	time.Sleep(3 * time.Second)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmd)
}

func TestAncestors2(t *testing.T) {
	testAncestorsN(t, 2)
}

func TestAncestors3(t *testing.T) {
	testAncestorsN(t, 3)
}

func TestAncestors4(t *testing.T) {
	testAncestorsN(t, 4)
}
