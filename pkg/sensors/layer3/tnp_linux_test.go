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

package layer3_test

import (
	"context"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/isovalent/hubble-fgs/pkg/netpol"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const curlTNPAllow = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "curl-allow"
  annotations:
    author: "Isovalent"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
`

const curlTNPDeny = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "curl-deny"
  annotations:
    author: "Isovalent"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectDenyRule"
    hook: "connect"
    action: "deny"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
`

const curlTNPDefaultAllow = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "curl-default-allow"
  annotations:
    author: "Isovalent"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "allow"
  rules:
  - description: "fooRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "255.255.255.255"
      ports:
        protocol: "TCP"
`

const curlTNPDefaultDeny = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "curl-default-deny"
  annotations:
    author: "Isovalent"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "deny"
  rules:
  - description: "fooRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "255.255.255.255"
      ports:
        protocol: "TCP"
`

type tnpTestFn func(t *testing.T, readyWG *sync.WaitGroup)

type tnpTest struct {
	name string
	tnp  string
	f    tnpTestFn
}

var tnpTests = []tnpTest{
	{"TNPAllow", curlTNPAllow, testTNPAllow},
	{"TNPDeny", curlTNPDeny, testTNPDeny},
	{"TNPDefaultAllow", curlTNPDefaultAllow, testTNPDefaultAllow},
	{"TNPDefaultDeny", curlTNPDefaultDeny, testTNPDefaultDeny},
}

func testTNPAllow(t *testing.T, readyWG *sync.WaitGroup) {
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("allowChecker").WithProcess(ec.NewProcessChecker().WithBinary(stringmatcher.Suffix("curl"))).WithPolicyInfo(ec.NewTNPInfoChecker().WithAction(tetragon.TNPAction_TNP_POLICY_ALLOW).WithPolicyName(stringmatcher.Full("curl-allow")).WithRuleName(stringmatcher.Full("connectAllowRule"))),
	)

	observertesthelper.ExecWGCurl(readyWG, 10, "127.0.0.1")

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testTNPDeny(t *testing.T, readyWG *sync.WaitGroup) {
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("denyChecker").WithProcess(ec.NewProcessChecker().WithBinary(stringmatcher.Suffix("curl"))).WithPolicyInfo(ec.NewTNPInfoChecker().WithAction(tetragon.TNPAction_TNP_POLICY_DENY).WithPolicyName(stringmatcher.Full("curl-deny")).WithRuleName(stringmatcher.Full("connectDenyRule"))),
	)

	err := observertesthelper.ExecWGCurl(readyWG, 0, "127.0.0.1", "--connect-timeout", "1")
	require.Error(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testTNPDefaultAllow(t *testing.T, readyWG *sync.WaitGroup) {
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("defaultAllowChecker").WithProcess(ec.NewProcessChecker().WithBinary(stringmatcher.Suffix("curl"))).WithPolicyInfo(ec.NewTNPInfoChecker().WithAction(tetragon.TNPAction_TNP_POLICY_DEFAULT_ALLOW).WithPolicyName(stringmatcher.Full("curl-default-allow"))),
	)

	err := observertesthelper.ExecWGCurl(readyWG, 10, "127.0.0.1")
	require.Error(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testTNPDefaultDeny(t *testing.T, readyWG *sync.WaitGroup) {
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("defaultDenyChecker").WithProcess(ec.NewProcessChecker().WithBinary(stringmatcher.Suffix("curl"))).WithPolicyInfo(ec.NewTNPInfoChecker().WithAction(tetragon.TNPAction_TNP_POLICY_DEFAULT_DENY).WithPolicyName(stringmatcher.Full("curl-default-deny"))),
	)

	err := observertesthelper.ExecWGCurl(readyWG, 0, "127.0.0.1", "--connect-timeout", "1")
	require.Error(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTNP(t *testing.T) {
	if !kernels.MinKernelVersion("5.15.0") || !utils.SupportAddAndFetch() {
		t.Skip()
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getLayer3Observer(t, ctx, tcpBasicConfig, true)

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	for _, test := range tnpTests {
		t.Logf("Running test: %s", test.name)
		if !t.Run(test.name, func(t *testing.T) {
			np, err := netpol.FromYAML(test.tnp)
			require.NoError(t, err)

			err = netpol.Add(np)
			require.NoError(t, err)
			t.Cleanup(func() { netpol.Delete(np) })

			test.f(t, &readyWG)
		}) {
			t.Logf("Test %s failed", test.name)
			break
		}
		t.Logf("Test %s was successful", test.name)
	}
}
