// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//

//go:build sudo_tests

package http_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	httpSens "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	layer3Testutil "github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorHttp")
	os.Exit(ec)
}

func httpConfig(port int) string {
	return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "http"
spec:
  parser:
    tls:
      enable: false
      selectors:
      - matchPorts:
        - 1
    http:
      enable: true
      selectors:
      - matchPorts:
        - %d
    tcp:
      enable: true
`, port)
}

func TestHttp11Curl(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "http-11-curl", nil)
}

func TestHttp11CurlCLI(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "http-11-curl-no-policy", nil)
}

func testHttp11Curl6(t *testing.T, CLISwitches bool) {
	t.Skip("TODO: http currently does not support ipv6")
	if v := "6.1.56"; !kernels.MinKernelVersion(v) {
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
		WithArguments(sm.Full("-6 http://www.google.com"))

	httpChecker := ec.NewHttpInfoChecker().
		WithRequest(ec.NewHttpRequestChecker().
			WithMethod(sm.Full("GET")).
			WithUri(sm.Full("/")).
			WithVersion(sm.Full("HTTP/1.1")).
			WithAgent(sm.Contains("curl")).
			WithHost(sm.Contains("www.google.com"))).
		WithResponse(ec.NewHttpResponseChecker().
			WithVersion(sm.Full("HTTP/1.1")).
			WithReason(sm.Full("OK")))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(80),
		ec.NewProcessHttpChecker("curlHttp").
			WithProcess(curlChecker).
			WithHttp(httpChecker),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: false},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{1}},
			{KeyPtr: &enterpriseOption.Config.EnableHTTPSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.HTTPSensorPorts, Value: []int{80}},
		}))
	}

	require.NoError(t, observertesthelper.WriteConfigFile(testConfigFile, enterpriseoth.EmptyTracingPolicy))

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	require.NoError(t, err)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	require.NoError(t, sockops.StartSockopsSensor(ctx))
	require.NoError(t, sockmap.StartSockmapSensor(ctx))
	require.NoError(t, httpSens.StartHttpProgs(ctx))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(httpConfig(80))
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "-6", "http://www.google.com")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestHttp11Curl6(t *testing.T) {
	testHttp11Curl6(t, false)
}

func TestHttp11Curl6CLI(t *testing.T) {
	testHttp11Curl6(t, true)
}

// nolint This is only used in a disabled test for now. Since we will re-enable that test
// soon, let's leave this and ignore dead code warnings.
func spawnHttp2Server(ctx context.Context, t *testing.T, ipv6 bool) string {
	handler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		})
	s := http.Server{
		Handler: handler,
	}
	if ipv6 {
		s.Addr = "[::1]:0"
	} else {
		s.Addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		t.Fatalf("spawnHttp2Server: failed to listen at %s: %s", s.Addr, err)
	}

	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
		ln.Close()
	}()
	s.Protocols = new(http.Protocols)
	s.Protocols.SetHTTP1(true)
	s.Protocols.SetUnencryptedHTTP2(true)
	go s.Serve(ln)

	return ln.Addr().String()
}

func testHttp20CurlPriorKnowledge(t *testing.T, CLISwitches bool) {
	t.Skipf("This test is currrently very flaky due to a kernel bug. TODO: Re-enable after this gets fixed upstream")

	if v := "6.1.56"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	http2Addr := spawnHttp2Server(ctx, t, false)
	http2Port, _ := strconv.ParseUint(strings.Split(http2Addr, ":")[1], 10, 32)

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-v4 --http2-prior-knowledge http://" + http2Addr))

	httpChecker := ec.NewHttpInfoChecker().
		WithRequest(ec.NewHttpRequestChecker().
			WithMethod(sm.Full("GET")).
			WithUri(sm.Full("/")).
			WithVersion(sm.Full("HTTP/2")).
			WithAgent(sm.Contains("curl")).
			WithHost(sm.Contains(http2Addr))).
		WithResponse(ec.NewHttpResponseChecker().
			WithVersion(sm.Full("HTTP/2")).
			WithReason(sm.Full("OK")))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(uint32(http2Port)),
		ec.NewProcessHttpChecker("curlHttp").
			WithProcess(curlChecker).
			WithHttp(httpChecker),
	)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: false},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{1}},
			{KeyPtr: &enterpriseOption.Config.EnableHTTPSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.HTTPSensorPorts, Value: []int{int(http2Port)}},
		}))
	}

	require.NoError(t, observertesthelper.WriteConfigFile(testConfigFile, enterpriseoth.EmptyTracingPolicy))

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	require.NoError(t, err)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	require.NoError(t, sockops.StartSockopsSensor(ctx))
	require.NoError(t, sockmap.StartSockmapSensor(ctx))
	require.NoError(t, httpSens.StartHttpProgs(ctx))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(httpConfig(int(http2Port)))
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "-v4", "--http2-prior-knowledge", "http://"+http2Addr)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestHttp20CurlPriorKnowledge(t *testing.T) {
	testHttp20CurlPriorKnowledge(t, false)
}

func TestHttp20CurlPriorKnowledgeCLI(t *testing.T) {
	testHttp20CurlPriorKnowledge(t, true)
}

func testHttp20CurlPriorKnowledge6(t *testing.T, CLISwitches bool) {
	t.Skip("TODO: http currently does not support ipv6")
	t.Skipf("This test is currrently very flaky due to a kernel bug. TODO: Re-enable after this gets fixed upstream")

	if v := "6.1.56"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	http2Addr := spawnHttp2Server(ctx, t, true)
	http2Port, _ := strconv.ParseUint(strings.Split(http2Addr, ":")[1], 10, 32)

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-v6 --http2-prior-knowledge http://" + http2Addr))

	httpChecker := ec.NewHttpInfoChecker().
		WithRequest(ec.NewHttpRequestChecker().
			WithMethod(sm.Full("GET")).
			WithUri(sm.Full("/")).
			WithVersion(sm.Full("HTTP/2")).
			WithAgent(sm.Contains("curl")).
			WithHost(sm.Contains(http2Addr))).
		WithResponse(ec.NewHttpResponseChecker().
			WithVersion(sm.Full("HTTP/2")).
			WithReason(sm.Full("OK")))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(uint32(http2Port)),
		ec.NewProcessHttpChecker("curlHttp").
			WithProcess(curlChecker).
			WithHttp(httpChecker),
	)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: false},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{1}},
			{KeyPtr: &enterpriseOption.Config.EnableHTTPSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.HTTPSensorPorts, Value: []int{int(http2Port)}},
		}))
	}

	require.NoError(t, observertesthelper.WriteConfigFile(testConfigFile, enterpriseoth.EmptyTracingPolicy))

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	require.NoError(t, err)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	require.NoError(t, sockops.StartSockopsSensor(ctx))
	require.NoError(t, sockmap.StartSockmapSensor(ctx))
	require.NoError(t, httpSens.StartHttpProgs(ctx))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(httpConfig(int(http2Port)))
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "-v6", "--http2-prior-knowledge", "http://"+http2Addr)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestHttp20CurlPriorKnowledge6(t *testing.T) {
	testHttp20CurlPriorKnowledge6(t, false)
}

func TestHttp20CurlPriorKnowledge6CLI(t *testing.T) {
	testHttp20CurlPriorKnowledge6(t, true)
}

func testLoadHttpSensor(t *testing.T, CLISwitches bool) {
	if v := "6.1.56"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}

	bpf.CheckOrMountCgroup2()

	config := httpConfig(80)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTLSSensor, Value: false},
			{KeyPtr: &enterpriseOption.Config.TLSSensorPorts, Value: []int{1}},
			{KeyPtr: &enterpriseOption.Config.EnableHTTPSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.HTTPSensorPorts, Value: []int{80}},
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

	httpSensor := httpSens.EnableHTTPParser(&tracingpolicy.GenericTracingPolicy{})
	b.Progs = append(b.Progs, httpSensor.Progs...)
	b.Maps = append(b.Maps, httpSensor.Maps...)

	require.NoError(t, observertesthelper.WriteConfigFile(testConfigFile, config))

	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	require.NoError(t, err)

	sensorProgs, sensorMaps := layer3Testutil.ProgsAndMaps(false, false, false)
	ni := uint(len(sensorProgs)) // next index

	sensorProgs = append(sensorProgs, []tus.SensorProg{
		tus.SensorProg{Name: "tg_http_sk_msg_fgs", Type: ebpf.SkMsg}, // Index ni
		tus.SensorProg{Name: "tg_http_sk_msg_fgs_response", Type: ebpf.SkMsg},
		tus.SensorProg{Name: "tg_http_sk_msg_fgs_request", Type: ebpf.SkMsg},
		tus.SensorProg{Name: "tg_http_sk_msg_get_more_headers", Type: ebpf.SkMsg},
		tus.SensorProg{Name: "tg_skmsg_http2", Type: ebpf.SkMsg},
		tus.SensorProg{Name: "tg_skskb_http_response", Type: ebpf.SkSKB},
		tus.SensorProg{Name: "tg_skskb_http_request", Type: ebpf.SkSKB},
		tus.SensorProg{Name: "tg_skskb_http_get_more_headers", Type: ebpf.SkSKB},
		tus.SensorProg{Name: "tg_skskb_http2", Type: ebpf.SkSKB},
		tus.SensorProg{Name: "tg_skskb_http_verdict", Type: ebpf.SkSKB},
		tus.SensorProg{Name: "tg_sockmap", Type: ebpf.SockOps}, //  ni + 10
	}...)

	require.NoError(t, layer3Testutil.AddToMap(sensorMaps, "tg_http_map", []uint{ni, ni + 1, ni + 2, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7, ni + 8, ni + 9}))

	sensorMaps = append(sensorMaps, tus.SensorMap{Name: "http1_calls", Progs: []uint{ni, ni + 1, ni + 2, ni + 3}})
	sensorMaps = append(sensorMaps, tus.SensorMap{Name: "http1_calls_skb", Progs: []uint{ni + 5, ni + 6, ni + 7, ni + 8, ni + 9}})
	sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_http_err_stats", Progs: []uint{ni, ni + 1, ni + 2, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7, ni + 8, ni + 9}})
	sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_http_filter_map", Progs: []uint{ni + 10}})

	// all but base and tg_sockmap
	require.NoError(t, layer3Testutil.AddToMap(sensorMaps, "tg_l3_tcpsk", []uint{ni, ni + 1, ni + 2, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7, ni + 8, ni + 9}))
	// all but tg_sockmap
	require.NoError(t, layer3Testutil.AddToMap(sensorMaps, "tcpmon_map", []uint{ni, ni + 1, ni + 2, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7, ni + 8, ni + 9}))

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestLoadHttpSensor(t *testing.T) {
	testLoadHttpSensor(t, false)
}

func TestLoadHttpSensorCLI(t *testing.T) {
	testLoadHttpSensor(t, true)
}
