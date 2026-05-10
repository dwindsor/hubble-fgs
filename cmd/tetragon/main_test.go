// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package tetragon

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

	eedefaults "github.com/isovalent/hubble-fgs/pkg/defaults"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "Exec")
	os.Exit(ec)
}

// The test starts tetragon with minimal setup and stops it
// when it observer is ready. By that time we should have
// exec events generated, make sure it's done.
func TestGeneratedExecEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Minimal config to start tetragon
	option.Config.ExportRateLimit = -1
	option.Config.DataCacheSize = 1024
	option.Config.ProcessCacheSize = 65536
	option.Config.BpfDir = defaults.DefaultMapPrefix
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.TracingPolicyDir = defaults.DefaultTpDir
	enterpriseOption.Config.PoliciesDir = eedefaults.DefaultPoliciesDir

	// Configure export file
	f, err := testutils.CreateExportFile(t)
	if err != nil {
		t.Fatalf("testutils.CreateExportFilefailed: %v\n", err)
	}
	defer f.Close()

	fname, err := testutils.GetExportFilename(t)
	if err != nil {
		t.Fatalf("testutils.GetExportFilename failed: %v\n", err)
	}
	option.Config.ExportFilename = fname

	var readyWg, pidWg sync.WaitGroup
	readyCalled := false
	// readyWg is for the `ready` callback
	readyWg.Add(1)
	ready := func() {
		readyWg.Done()
		readyCalled = true
	}

	// Start tetragon in separate process so we can keep the whole
	// export/server machinery running until we get expected results.
	pidWg.Go(func() {
		err = tetragonExecuteCtx(ctx, cancel, ready)
		if !readyCalled {
			ready()
		}
		assert.NoError(t, err)
	})

	// Wait till tetragon's observer is up and running
	readyWg.Wait()

	// Make sure exec event with pid 1 was generated
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").WithProcess(
			ec.NewProcessChecker().WithPid(1)),
	)

	// Try it 5 times and make sure exporter is up and processed all data
	// in case it lags for some reason like slow CI server.
	cnt := 0
	for cnt < 5 {
		if err = jsonchecker.JsonTestCheck(t, checker); err == nil {
			break
		}
		time.Sleep(time.Second)
		cnt++
	}

	cancel()
	// Wait till tetragon's goroutine exits
	pidWg.Wait()
	assert.NoError(t, err)
}
