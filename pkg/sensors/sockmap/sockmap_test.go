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
	"runtime"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
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
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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

var (
	tlsConfigCG = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "cgroup"
      selectors:
      - matchports:
        - 443
    tcp:
      enable: true
`
)

func maxKernelVersion(max string) bool {
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return int64(kernelVer) < kernels.KernelStringToNumeric(max)
}

func TestTLS13(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	// FIXME: remove this restriction once the kernel bug impacting TLS is fixed in 6.1.X
	if v := "6.1.0"; !maxKernelVersion(v) {
		t.Skipf("TLS parser is currently flaky on this kernel version (%v), skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("--tlsv1.3 -4 https://www.google.com"))

	tlsChecker := ec.NewTlsChecker("curlTls").
		WithProcess(curlChecker).
		WithParent(selfChecker).
		WithNegotiatedVersion(sm.Full("TLS1.3")).
		WithClientVersion(sm.Full("TLS1.2")).
		WithServerVersion(sm.Full("TLS1.2")).
		WithSniType(sm.Full("host_name")).
		WithSniName(sm.Contains("www.google.com")).
		WithClientFlags(sm.Contains("ExtVersion")).
		WithServerFlags(sm.Contains("ExtVersion"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observertesthelper.WriteConfigFile(testConfigFile, tlsConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.3", "-4", "https://www.google.com")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTLS12(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	// FIXME: remove this restriction once the kernel bug impacting TLS is fixed in 6.1.X
	if v := "6.1.0"; !maxKernelVersion(v) {
		t.Skipf("TLS parser is currently flaky on this kernel version (%v), skipping", v)
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

	tlsChecker := ec.NewTlsChecker("curlTls").
		WithProcess(curlChecker).
		WithParent(selfChecker).
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
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	if err := observertesthelper.WriteConfigFile(testConfigFile, tlsConfig); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadTlsSensor(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}

	bpf.CheckOrMountCgroup2()

	config := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
`

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "bpf_sockmap", Type: ebpf.SockOps},
		1: tus.SensorProg{Name: "setsockopt", Type: ebpf.CGroupSockopt},
		2: tus.SensorProg{Name: "bpf_tls_sk_msg_fgs", Type: ebpf.SkMsg},
		3: tus.SensorProg{Name: "bpf_tls_skskb_verdict", Type: ebpf.SkSKB},
	}

	var sensorMaps = []tus.SensorMap{
		// all but base and bpf_sockmap
		tus.SensorMap{Name: "tg_tls_map", Progs: []uint{1, 2, 3}},

		// all but base and bpf_tls_skskb_verdict
		tus.SensorMap{Name: "tg_tls_filter_map", Progs: []uint{0, 1}},

		// bpf_sockmap
		tus.SensorMap{Name: "tg_tls_sock_map", Progs: []uint{0}},

		// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict
		tus.SensorMap{Name: "tg_bottles", Progs: []uint{2, 3}},
		tus.SensorMap{Name: "tg_bottle_map_stats", Progs: []uint{2, 3}},
		tus.SensorMap{Name: "tg_tls_parser_stats", Progs: []uint{2, 3}},

		// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict, base
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{2, 3}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadSensors(sens)
}

func TestLoadTlsCGSensor(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}

	bpf.CheckOrMountCgroup2()

	config := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "cgroup"
      selectors:
      - matchports:
        - 443
`

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "tls_inet_send", Type: ebpf.CGroupSKB},
		1: tus.SensorProg{Name: "tls_inet_recv", Type: ebpf.CGroupSKB},
	}

	var sensorMaps = []tus.SensorMap{
		// send and recv
		tus.SensorMap{Name: "tg_tls_map", Progs: []uint{0, 1}},

		// send only
		tus.SensorMap{Name: "tg_tls_filter_map", Progs: []uint{0, 1}},

		// send and recv
		tus.SensorMap{Name: "tg_bottles", Progs: []uint{0, 1}},
		tus.SensorMap{Name: "tg_bottle_map_stats", Progs: []uint{0, 1}},
		tus.SensorMap{Name: "tg_tls_parser_stats", Progs: []uint{0, 1}},

		// send and recv
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadSensors(sens)
}

func TestCGTLS13(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}

	// FIXME: remove this restriction once the kernel bug impacting TLS is fixed in 6.1.X
	if v := "6.1.0"; !maxKernelVersion(v) {
		t.Skipf("TLS parser is currently flaky on this kernel version (%v), skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("--tlsv1.3 -4 https://www.google.com"))

	tlsChecker := ec.NewTlsChecker("curlTls").
		WithProcess(curlChecker).
		WithParent(selfChecker).
		WithNegotiatedVersion(sm.Full("TLS1.3")).
		WithClientVersion(sm.Full("TLS1.2")).
		WithServerVersion(sm.Full("TLS1.2")).
		WithSniType(sm.Full("host_name")).
		WithSniName(sm.Contains("www.google.com")).
		WithClientFlags(sm.Contains("ExtVersion")).
		WithServerFlags(sm.Contains("ExtVersion"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observertesthelper.WriteConfigFile(testConfigFile, tlsConfigCG); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.3", "-4", "https://www.google.com")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestCGTLS12(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}

	// FIXME: remove this restriction once the kernel bug impacting TLS is fixed in 6.1.X
	if v := "6.1.0"; !maxKernelVersion(v) {
		t.Skipf("TLS parser is currently flaky on this kernel version (%v), skipping", v)
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

	tlsChecker := ec.NewTlsChecker("curlTls").
		WithProcess(curlChecker).
		WithParent(selfChecker).
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
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(443),
		tlsChecker,
	)

	if err := observertesthelper.WriteConfigFile(testConfigFile, tlsConfigCG); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
