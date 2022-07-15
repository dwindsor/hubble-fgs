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
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/isovalent/hubble-fgs/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	selfBinary  string
	fgsLib      string
	cmdWaitTime time.Duration
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")

	bpf.SetMapPrefix("testObserver")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
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
		WithBinary(sm.Suffix(selfBinary))

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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(80)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
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
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	http2Addr := spawnHttp2Server(ctx, t)
	http2Port, _ := strconv.ParseUint(strings.Split(http2Addr, ":")[1], 10, 32)

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary))

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

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "-v4", "--http2-prior-knowledge", "http://"+http2Addr)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
