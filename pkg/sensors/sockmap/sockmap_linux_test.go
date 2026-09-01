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
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

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

func testTLS13(t *testing.T, CLISwitches, cgroup bool) {
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
		WithArguments(sm.Full("--curves X25519 --tlsv1.3 -4 https://www.google.com"))

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

	tracingPolicy := tlsConfig
	mode := "socket"
	if cgroup {
		tracingPolicy = tlsConfigCG
		mode = "cgroup"
	}

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.TLSSensorMode, Value: mode},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{443}},
		}))
	}

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	require.NoError(t, sockops.StartSockopsSensor(ctx))
	require.NoError(t, StartSockmapSensor(ctx))

	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(tracingPolicy)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--curves", "X25519", "--tlsv1.3", "-4", "https://www.google.com")

	require.NoError(t, jsonchecker.JsonTestCheck(t, checker))
}

func TestTLS13(t *testing.T) {
	testTLS13(t, false, false)
}

func TestCGTLS13(t *testing.T) {
	testTLS13(t, false, true)
}

func TestTLS13CLI(t *testing.T) {
	testTLS13(t, true, false)
}

func TestCGTLS13CLI(t *testing.T) {
	testTLS13(t, true, true)
}

func testTLS12(t *testing.T, CLISwitches, cgroup bool) {
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

	tracingPolicy := tlsConfig
	mode := "socket"
	if cgroup {
		tracingPolicy = tlsConfigCG
		mode = "cgroup"
	}

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.TLSSensorMode, Value: mode},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{443}},
		}))
	}

	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	require.NoError(t, sockops.StartSockopsSensor(ctx))
	require.NoError(t, StartSockmapSensor(ctx))

	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(tracingPolicy)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	require.NoError(t, jsonchecker.JsonTestCheck(t, checker))
}

func TestTLS12(t *testing.T) {
	testTLS12(t, false, false)
}

func TestCGTLS12(t *testing.T) {
	testTLS12(t, false, true)
}

func TestTLS12CLI(t *testing.T) {
	testTLS12(t, true, false)
}

func TestCGTLS12CLI(t *testing.T) {
	testTLS12(t, true, true)
}

func testLoadTlsSensor(t *testing.T, CLISwitches bool) {
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

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.TLSSensorMode, Value: "socket"},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{443}},
		}))
		config = enterpriseoth.EmptyTracingPolicy
	}

	layer3.BaseLoaded = false

	b := base.GetInitialSensorTest(t)

	require.NoError(t, layer3.EnableLayer3Progs())
	layer3Sensor := layer3.Layer3InitialSensor()
	b.Maps = append(b.Maps, layer3Sensor.Maps...)
	b.Progs = append(b.Progs, layer3Sensor.Progs...)

	sockopsSensor, err := sockops.Builder(&tracingpolicy.GenericTracingPolicy{}, "__sockops_init_sensors__")
	require.NoError(t, err)
	b.Progs = append(b.Progs, sockopsSensor.Progs...)
	b.Maps = append(b.Maps, sockopsSensor.Maps...)

	sockmapSensor := enableTLSParser(&tracingpolicy.GenericTracingPolicy{}, false)
	b.Progs = append(b.Progs, sockmapSensor.Progs...)
	b.Maps = append(b.Maps, sockmapSensor.Maps...)

	err = observertesthelper.WriteConfigFile(testConfigFile, config)
	require.NoError(t, err)

	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	require.NoError(t, err)

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

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		tus.SensorMap{Name: "tg_tls_filter_map", Progs: []uint{ni, ni + 1}},
		tus.SensorMap{Name: "tg_tls_sock_map", Progs: []uint{ni}},
		tus.SensorMap{Name: "tg_tls_parser_stats", Progs: []uint{ni + 2, ni + 3}},
	}...)

	// all but base and tg_sockmap
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_tls_map", []uint{ni + 1, ni + 2, ni + 3}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_tls_map_stats", []uint{ni + 2}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_bottles", []uint{ni + 2, ni + 3}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_bottle_map_stats", []uint{ni + 2, ni + 3}))

	// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict, base
	require.NoError(t, testutil.AddToMap(sensorMaps, "tcpmon_map", []uint{ni + 2, ni + 3}))

	// bpf_tls_sk_msg_fgs, bpf_tls_skskb_verdict
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_l3_tcpsk", []uint{ni + 2, ni + 3}))

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestLoadTlsSensor(t *testing.T) {
	testLoadTlsSensor(t, false)
}

func TestLoadTlsSensorCLI(t *testing.T) {
	testLoadTlsSensor(t, true)
}

func testLoadTlsCGSensor(t *testing.T, CLISwitches bool) {
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

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.TLSSensorMode, Value: "cgroup"},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{443}},
		}))
		config = enterpriseoth.EmptyTracingPolicy
	}

	layer3.BaseLoaded = false

	b := base.GetInitialSensorTest(t)

	require.NoError(t, layer3.EnableLayer3Progs())
	layer3Sensor := layer3.Layer3InitialSensor()
	b.Maps = append(b.Maps, layer3Sensor.Maps...)
	b.Progs = append(b.Progs, layer3Sensor.Progs...)

	sockmapSensor := enableTLSParser(&tracingpolicy.GenericTracingPolicy{}, true)
	b.Progs = append(b.Progs, sockmapSensor.Progs...)
	b.Maps = append(b.Maps, sockmapSensor.Maps...)

	err := observertesthelper.WriteConfigFile(testConfigFile, config)
	require.NoError(t, err)

	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	require.NoError(t, err)

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

	// send and recv
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_tls_map", []uint{ni, ni + 1}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_tls_map_stats", []uint{ni}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_l3_sk", []uint{ni, ni + 1}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_l3_tcpsk", []uint{ni, ni + 1}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tcpmon_map", []uint{ni, ni + 1}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_bottles", []uint{ni, ni + 1}))
	require.NoError(t, testutil.AddToMap(sensorMaps, "tg_bottle_map_stats", []uint{ni, ni + 1}))

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestLoadTlsCGSensor(t *testing.T) {
	testLoadTlsCGSensor(t, false)
}

func TestLoadTlsCGSensorCLI(t *testing.T) {
	testLoadTlsCGSensor(t, true)
}
