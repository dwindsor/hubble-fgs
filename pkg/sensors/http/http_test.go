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

package http_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
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
apiVersion: hubble-enterprise.io/v1
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
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-4 http://www.google.com"))

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
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(80),
		ec.NewProcessHttpChecker().
			WithProcess(curlChecker).
			WithHttp(httpChecker),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(80)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "-4", "http://www.google.com")

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// nolint This is only used in a disabled test for now. Since we will re-enable that test
// soon, let's leave this and ignore dead code warnings.
func spawnHttp2Server(ctx context.Context, t *testing.T) string {
	handler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		})
	s := http.Server{
		Addr:    "127.0.0.1:0",
		Handler: h2c.NewHandler(handler, &http2.Server{}),
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
	go s.Serve(ln)

	return ln.Addr().String()
}

func TestHttp20CurlPriorKnowledge(t *testing.T) {
	t.Skipf("This test is currrently very flaky due to a kernel bug. TODO: Re-enable after this gets fixed upstream")

	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	http2Addr := spawnHttp2Server(ctx, t)
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
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationPort(uint32(http2Port)),
		ec.NewProcessHttpChecker().
			WithProcess(curlChecker).
			WithHttp(httpChecker),
	)

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(int(http2Port))); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "-v4", "--http2-prior-knowledge", "http://"+http2Addr)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadHttpSensor(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(80)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(80)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sensorProgs := []tus.SensorProg{
		0:  tus.SensorProg{Name: "bpf_http_sk_msg_fgs", Type: ebpf.SkMsg},
		1:  tus.SensorProg{Name: "event_tcp_connect", Type: ebpf.Kprobe},
		2:  tus.SensorProg{Name: "event_tcp_close", Type: ebpf.Kprobe},
		3:  tus.SensorProg{Name: "event_sys_listen", Type: ebpf.Kprobe},
		4:  tus.SensorProg{Name: "event_tcp_v4_send_check", Type: ebpf.Kprobe},
		5:  tus.SensorProg{Name: "bpf_http_sk_msg_fgs_response", Type: ebpf.SkMsg},
		6:  tus.SensorProg{Name: "bpf_http_sk_msg_fgs_request", Type: ebpf.SkMsg},
		7:  tus.SensorProg{Name: "bpf_http_sk_msg_get_more_headers", Type: ebpf.SkMsg},
		8:  tus.SensorProg{Name: "bpf_skmsg_http2", Type: ebpf.SkMsg},
		9:  tus.SensorProg{Name: "bpf_skskb_http_response", Type: ebpf.SkSKB},
		10: tus.SensorProg{Name: "bpf_skskb_http_request", Type: ebpf.SkSKB},
		11: tus.SensorProg{Name: "bpf_skskb_get_more_headers", Type: ebpf.SkSKB},
		12: tus.SensorProg{Name: "bpf_skskb_http2", Type: ebpf.SkSKB},
		13: tus.SensorProg{Name: "bpf_skskb_http_verdict", Type: ebpf.SkSKB},
		14: tus.SensorProg{Name: "bpf_sockmap", Type: ebpf.SockOps},

		// new accept sensor
		15: tus.SensorProg{Name: "event_tcp_acceptret", Type: ebpf.TracePoint},
		16: tus.SensorProg{Name: "event_tcp_accept4ret", Type: ebpf.TracePoint},

		// IPv6 sensor
		17: tus.SensorProg{Name: "event_tcp_v6_send_check", Type: ebpf.Kprobe},
	}

	sensorMaps := []tus.SensorMap{
		// base, event_tcp4_connect, event_sys_listen, event_tcp_v4_send_check
		tus.SensorMap{Name: "execve_map", Progs: []uint{1, 3, 4, 15, 16, 17}},

		// all but base and bpf_sockmap
		tus.SensorMap{Name: "socket_map", Progs: []uint{1, 2, 3, 4, 15, 16, 17}},

		// event_tcp4_connect, event_tcp4_close, event_sys_listen
		tus.SensorMap{Name: "socket_map_stats", Progs: []uint{1, 2, 3, 15, 16}},

		// all but bpf_sockmap
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17}},

		// event_tcp_acceptret, event_tcp_accept4ret
		tus.SensorMap{Name: "fd_lookup_config_map", Progs: []uint{15, 16}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}
