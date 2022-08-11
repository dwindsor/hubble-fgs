//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package sockmap

import (
	"context"
	"os"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorSockmap")
	os.Exit(ec)
}

var (
	tlsConfig = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "socket"
      selectors:
      - matchports:
        - 443
    tcp:
      enable: true
`
)

func TestTLS13(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("--tlsv1.3 -4 https://www.google.com"))

	tlsChecker := ec.NewTlsChecker().
		WithProcess(curlChecker).
		WithNegotiatedVersion(sm.Full("TLS1.3")).
		WithClientVersion(sm.Full("TLS1.2")).
		WithServerVersion(sm.Full("TLS1.2")).
		WithSniType(sm.Full("host_name")).
		WithSniName(sm.Contains("www.google.com")).
		WithClientFlags(sm.Contains("ExtVersion")).
		WithServerFlags(sm.Contains("ExtVersion"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tlsConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "--tlsv1.3", "-4", "https://www.google.com")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTLS12(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("--tlsv1.2 --tls-max 1.2 -4 https://www.google.com/"))

	tlsChecker := ec.NewTlsChecker().
		WithProcess(curlChecker).
		WithClientVersion(sm.Full("TLS1.2")).
		WithServerVersion(sm.Full("TLS1.2")).
		WithSniType(sm.Full("host_name")).
		WithSniName(sm.Contains("www.google.com")).
		WithClientFlags(sm.Full("")).
		WithServerFlags(sm.Full("")).
		WithCertificates(ec.NewStringListMatcher().
			WithOperator(lm.Unordered).
			WithValues(
				sm.Full("CN=www.google.com"),
				sm.Full("CN=GTS CA 1C3,O=Google Trust Services LLC,C=US"),
				sm.Full("CN=GTS Root R1,O=Google Trust Services LLC,C=US"),
			))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	if err := observer.WriteConfigFile(testConfigFile, tlsConfig); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
