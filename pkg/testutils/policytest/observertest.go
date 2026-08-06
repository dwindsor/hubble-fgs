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

package policytest

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	oss "github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/tetragoninfo"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

var getAgentInfo = sync.OnceValue(func() *tetragoninfo.Info {
	res := tetragoninfo.Gather()
	return tetragoninfo.Decode(res)
})

// DoObserverTest runs a policytest registered with the OSS policytest framework
// (github.com/cilium/tetragon/pkg/testutils/policytest), but loads the enterprise base
// sensor and observer instead of the OSS ones. This is required for enterprise-only
// sensors (e.g. http, sockmap, layer3, socktrack) that depend on maps/programs which only
// the enterprise base sensor provides.
func DoObserverTest(t *testing.T, testpolicyName string, params map[string]any) {
	t.Helper()
	pts := oss.AllPolicyTests.GetByName(testpolicyName)
	if len(pts) == 0 {
		t.Fatalf("no testpolicy with name %q found", testpolicyName)
	} else if len(pts) > 1 {
		t.Fatalf(">1 testpolicies with name %q found", testpolicyName)
	}
	pt := pts[0]

	if pt.ShouldSkip != nil {
		skipInfo := oss.SkipInfo{AgentInfo: getAgentInfo(), ParamValues: oss.ParamVals(params)}
		if skipReason := pt.ShouldSkip(&skipInfo); skipReason != "" {
			t.Skip(skipReason)
		}
	}

	// sock_ops/sockmap-based sensors (http, layer3, sockmap) need a cgroup2 mount to attach to.
	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	conf := &oss.Conf{
		BinsDir: testutils.RepoRootPath("contrib/tester-progs"),
		TestConf: &oss.TestConf{
			ParamValues: params,
		},
	}
	policyStr, cleanupFn, err := pt.Policy(conf)
	if err != nil {
		t.Fatalf("failed to generate policy: %s", err)
	}
	t.Cleanup(cleanupFn)

	policyFile, err := os.CreateTemp("", "tetragon-policy-"+t.Name()+"-*.txt")
	if err != nil {
		t.Fatalf("failed to create policy file: %s", err)
	}
	policyFile.WriteString(string(policyStr))
	policyFile.Close()
	policyFname := policyFile.Name()

	b := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, b, policyFname, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithBase error: %s", err)
	}

	for _, s := range pt.Scenarios {
		observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
		readyWG.Wait()

		scenario := s(conf)
		if err := scenario.Trigger.Trigger(ctx); err != nil {
			t.Fatalf("failed to trigger scenario %s: %v", scenario.Name, err)
		}

		err = jsonchecker.JsonTestCheckExpect(t, scenario.EventChecker, scenario.ExpectCheckerFailure)
		require.NoError(t, err)
	}
}
