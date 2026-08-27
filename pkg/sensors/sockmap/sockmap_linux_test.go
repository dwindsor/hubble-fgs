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

package sockmap

import (
	"context"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"

	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"
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
      - matchPorts:
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
      - matchPorts:
        - 443
    tcp:
      enable: true
`
)

func TestTLS13(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
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

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	tp, err := tracingpolicy.FromYAML(tlsConfig)
	require.NoError(t, err)

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	require.NoError(t, err)

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
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
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
				// Something changed on Google's end and we now see one of two
				// possible certificates here, so match either one
				sm.Regex("(CN=WR2,O=Google Trust Services|CN=GTS CA 1C3,O=Google Trust Services LLC),C=US"),
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

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	tp, err := tracingpolicy.FromYAML(tlsConfig)
	require.NoError(t, err)

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	require.NoError(t, err)

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
      - matchPorts:
        - 443
    tcp:
      enable: true
`

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	layer3.BaseLoaded = false

	b := base.GetInitialSensorTest(t)

	require.NoError(t, layer3.EnableLayer3Progs())

	layer3Sensor := layer3.Layer3InitialSensor()

	b.Maps = append(b.Maps, layer3Sensor.Maps...)
	b.Progs = append(b.Progs, layer3Sensor.Progs...)
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithBase error: %s", err)
	}

	sensorProgs, sensorMaps := testutil.ProgsAndMaps(false, false, false)

	// If we base all indices into the progs map from "ni" then we can add extra programs
	// in front of these and just set ni to the number of programs. This supports the option
	// to make socktrack enabled by default, but doesn't require it.
	ni := uint(len(sensorProgs)) // next index

	sensorProgs = append(sensorProgs, []tus.SensorProg{
		tus.SensorProg{Name: "tg_sockmap", Type: ebpf.SockOps}, // index ni
		tus.SensorProg{Name: "tg_setsockopt", Type: ebpf.CGroupSockopt},
		tus.SensorProg{Name: "bpf_tls_sk_msg_fgs", Type: ebpf.SkMsg},
		tus.SensorProg{Name: "bpf_tls_skskb_verdict", Type: ebpf.SkSKB}, // index ni + 3
	}...)

	// all but base and tg_sockmap
	testutil.AddToMap(sensorMaps, "tg_tls_map", []uint{ni + 1, ni + 2, ni + 3})

	// all but base and bpf_tls_skskb_verdict
	testutil.AddToMap(sensorMaps, "tg_tls_filter_map", []uint{ni, ni + 1})

	// tg_sockmap
	testutil.AddToMap(sensorMaps, "tg_tls_sock_map", []uint{ni})

	// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict
	testutil.AddToMap(sensorMaps, "tg_bottles", []uint{ni + 2, ni + 3})
	testutil.AddToMap(sensorMaps, "tg_bottle_map_stats", []uint{ni + 2, ni + 3})
	testutil.AddToMap(sensorMaps, "tg_tls_parser_stats", []uint{ni + 2, ni + 3})
	testutil.AddToMap(sensorMaps, "tg_tls_parser_stats", []uint{ni + 2, ni + 3})
	testutil.AddToMap(sensorMaps, "tg_l3_tcpsk", []uint{ni + 2, ni + 3})

	// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict, base
	testutil.AddToMap(sensorMaps, "tcpmon_map", []uint{ni + 2, ni + 3})

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
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
      - matchPorts:
        - 443
    tcp:
      enable: true
`

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	layer3.BaseLoaded = false

	b := base.GetInitialSensorTest(t)

	require.NoError(t, layer3.EnableLayer3Progs())

	layer3Sensor := layer3.Layer3InitialSensor()

	b.Maps = append(b.Maps, layer3Sensor.Maps...)
	b.Progs = append(b.Progs, layer3Sensor.Progs...)
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithBase error: %s", err)
	}

	sensorProgs, sensorMaps := testutil.ProgsAndMaps(false, false, false)

	// If we base all indices into the progs map from "ni" then we can add extra programs
	// in front of these and just set ni to the number of programs. This supports the option
	// to make socktrack enabled by default, but doesn't require it.
	ni := uint(len(sensorProgs)) // next index

	sensorProgs = append(sensorProgs, []tus.SensorProg{
		tus.SensorProg{Name: "tls_inet_send", Type: ebpf.CGroupSKB}, // index ni
		tus.SensorProg{Name: "tls_inet_recv", Type: ebpf.CGroupSKB}, // index ni + 1
	}...)

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		// send only
		tus.SensorMap{Name: "tg_tls_filter_map", Progs: []uint{ni, ni + 1}},

		// send and recv
		tus.SensorMap{Name: "tg_tls_parser_stats", Progs: []uint{ni, ni + 1}},
	}...)

	// the index of tg_event_tcp_sockops is not known outside of ProgsAndMaps,
	// so resolve the whole list by name
	bottleProgs := []string{"tls_inet_send", "tls_inet_recv", "tg_event_tcp_sockops", "tg_event_tcp_close"}

	sensorMaps = append(sensorMaps,
		testutil.SensorMapByProgName(sensorProgs, "tg_bottles", bottleProgs),
		testutil.SensorMapByProgName(sensorProgs, "tg_bottle_map_stats", bottleProgs),
	)

	// send and recv
	testutil.AddToMap(sensorMaps, "tg_tls_map", []uint{ni, ni + 1})
	testutil.AddToMap(sensorMaps, "tg_l3_sk", []uint{ni, ni + 1})
	testutil.AddToMap(sensorMaps, "tg_l3_tcpsk", []uint{ni, ni + 1})
	testutil.AddToMap(sensorMaps, "tcpmon_map", []uint{ni, ni + 1})

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestCGTLS13(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
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

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	tp, err := tracingpolicy.FromYAML(tlsConfigCG)
	require.NoError(t, err)

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	require.NoError(t, err)

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
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
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
				// Something changed on Google's end and we now see one of two
				// possible certificates here, so match either one
				sm.Regex("(CN=WR2,O=Google Trust Services|CN=GTS CA 1C3,O=Google Trust Services LLC),C=US"),
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

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	tp, err := tracingpolicy.FromYAML(tlsConfigCG)
	require.NoError(t, err)

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	require.NoError(t, err)

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
