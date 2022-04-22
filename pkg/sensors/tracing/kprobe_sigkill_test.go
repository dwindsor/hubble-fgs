//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tracing

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

func testContribPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "..", "contrib", fname)
}

func logOut(t *testing.T, prefix string, rd *bufio.Reader) {
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("error reading %s: %s", prefix, err)
			}
			return
		}
		t.Logf("%s: %s", prefix, line)
	}
}

func TestKprobeSigkill(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testContribPath("sigkill-tester/sigkill-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}

	// The first thing sigkil-tester will do is print the child PID.  So we
	// make sure to get that to use it in the spec. Next, it will print
	// messages, so we print those into the testing log.
	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			logOut(t, "stdout> ", testPipes.StdoutRd)
		}()
		go func() {
			logOut(t, "stderr> ", testPipes.StderrRd)
		}()
		return pidStr
	}

	kataRun := false
	if os.Getenv("FGS_KATA_RUNNER") == "1" {
		t.Log("running inside kata...")
		kataRun = true
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
			// NB: if this is a kata run, the pid that the sigkill-tester will print,
			// will be inside the namespace.
			"NamespacePID": fmt.Sprintf("%t", kataRun),
		}
		specName, err := testutils.GetSpecFromTemplate("sigkill.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	pidStr := getPID()
	pidStr = strings.TrimSuffix(pidStr, "\n")
	specFname := makeSpecFile(pidStr)
	t.Logf("child pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, specFname, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_lseek").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(5555),
		}).
		WithAction(fgs.KprobeAction_KPROBE_ACTION_SIGKILL)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)
	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}
