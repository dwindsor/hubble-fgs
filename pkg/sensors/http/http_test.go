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

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"
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
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
	jsonRetries    = 10
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
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
  description: "http parser spec"
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
`, port)
}

func TestHttp11Curl(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("-4 http://www.google.com"),
	)

	httpCh := ec.NewHTTPChecker().
		WithRequestMethod("GET").
		WithRequestURI("/").
		WithRequestVersion("HTTP/1.1").
		WithRequestAgent(ec.ContainsStringMatch("curl")).
		WithRequestHost(ec.ContainsStringMatch("www.google.com")).
		WithResponseVersion("HTTP/1.1").
		WithResponseReason("OK")

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(80).
			End(),
		ec.NewHTTPEventChecker().
			HasProcess(curlChecker).
			HasHTTP(httpCh).
			End(),
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
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	observer.ExecWGCurl(&readyWG, "-4", "http://www.google.com")

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func spawnHttp2Server(t *testing.T, ctx context.Context) string {
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
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	http2Addr := spawnHttp2Server(t, ctx)
	http2Port, _ := strconv.ParseUint(strings.Split(http2Addr, ":")[1], 10, 32)

	bpf.CheckOrMountCgroup2()
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"),
		ec.FullStringMatch("-v4 --http2-prior-knowledge http://"+http2Addr),
	)

	httpCh := ec.NewHTTPChecker().
		WithRequestMethod("GET").
		WithRequestURI("/").
		WithRequestVersion("HTTP/2").
		WithRequestAgent(ec.ContainsStringMatch("curl")).
		WithRequestHost(ec.ContainsStringMatch(http2Addr)).
		WithResponseVersion("HTTP/2").
		WithResponseReason("OK")

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewConnectEventChecker().
			HasDstPort(uint32(http2Port)).
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),

		ec.NewHTTPEventChecker().
			HasProcess(curlChecker).
			HasHTTP(httpCh).
			End(),
	)

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(int(http2Port))); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	observer.ExecWGCurl(&readyWG, "-v4", "--http2-prior-knowledge", "http://"+http2Addr)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}
