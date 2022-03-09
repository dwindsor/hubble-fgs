//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func TestKprobeNSChanges(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("matchNamespaceChanges requires at least 5.3.0 version")
	}

	kataRun := false
	if os.Getenv("FGS_KATA_RUNNER") == "1" {
		t.Log("running inside kata...")
		kataRun = true
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testContribPath("namespace-tester/test_ns")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		logOut(t, "stdout> ", testPipes.StdoutRd)
	}()

	go func() {
		logOut(t, "stderr> ", testPipes.StderrRd)
	}()

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
			// NB: if this is a kata run, the pid that the ns-tester will print,
			// will be inside the namespace.
			"NamespacePID": fmt.Sprintf("%t", kataRun),
		}
		specName, err := testutils.GetSpecFromTemplate("nschanges.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	pidStr := strconv.Itoa(os.Getpid())
	specFname := makeSpecFile(pidStr)
	t.Logf("pid is %s and spec file is %s", pidStr, specFname)

	obs, err := getDefaultObserverWithWatchers(t, withConfig(specFname), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("strange.txt"), ec.FullStringMatch(""))
	writeArg1 = ec.GenericArgBytesCheck([]byte("testdata\x00"))
	writeArg2 = ec.GenericArgSizeCheck(9)
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2}).
		WithAction(fgs.KprobeAction_KPROBE_ACTION_POST)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			End(),
	)
	err = JsonTestCheck(t, &checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}
