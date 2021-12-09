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
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int
)

const (
	exportFile     = "/tmp/hubble-fgs.gotest"
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
	jsonRetries    = 10
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
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

var (
	tlstc = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls"
spec:
  description: "tls parser spec"
  parser:
    tls:
      enable: true
      mode: "tc"
`
)

func TestTCTLS13(t *testing.T) {
	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("--tlsv1.3 -4 https://www.google.com"),
	)

	tlsCh := ec.NewTlsChecker().
		WithNegotiatedVersion("TLS1.3").
		WithClientVersion("TLS1.2").
		WithServerVersion("TLS1.2").
		WithSniType("host_name").
		WithSniName("www.google.com").
		WithClientFlags("ExtVersion").
		WithServerFlags("ExtVersion")

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(443).
			End(),
		ec.NewTlsEventChecker().
			HasProcess(curlChecker).
			HasTls(tlsCh).
			End(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, obs, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "--tlsv1.3", "-4", "https://www.google.com")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func TestTCTLS12(t *testing.T) {
	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("-4 https://tls-v1-2.badssl.com:1012/"),
	)
	tlsCh := ec.NewTlsChecker().
		WithClientVersion("TLS1.2").
		WithServerVersion("TLS1.2").
		WithSniType("host_name").
		WithSniName("tls-v1-2.badssl.com").
		WithClientFlags("ExtVersion").
		WithServerFlags("").
		WithCertificates([]ec.StringArg{
			"CN=*.badssl.com,O=Lucas Garron Torres,L=Walnut Creek,ST=California,C=US",
			"CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
		})

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(1012).
			End(),
		ec.NewTlsEventChecker().
			HasProcess(curlChecker).
			HasTls(tlsCh).
			End(),
	)

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, obs, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "-4", "https://tls-v1-2.badssl.com:1012/")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
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
      - matchports:
        - 1
    http:
      enable: true
      selectors:
      - matchports:
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

	httpCh := ec.NewHttpChecker().
		WithRequestMethod("GET").
		WithRequestUri("/").
		WithRequestVersion("HTTP/1.1").
		WithRequestAgent(ec.ContainsStringMatch("curl")).
		WithRequestHost(ec.ContainsStringMatch("www.google.com")).
		WithResponseVersion("HTTP/1.1").
		WithResponseReason("OK")

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(80).
			End(),
		ec.NewHttpEventChecker().
			HasProcess(curlChecker).
			HasHttp(httpCh).
			End(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(80)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, obs, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "-4", "http://www.google.com")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func http2Server(ctx context.Context, port int) {
	handler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		})
	s := http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: h2c.NewHandler(handler, &http2.Server{}),
	}
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
	}()
	s.ListenAndServe()
}

func TestHttp20CurlPriorKnowledge(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	httpCh := ec.NewHttpChecker().
		WithRequestMethod("GET").
		WithRequestUri("/").
		WithRequestVersion("HTTP/2").
		WithRequestAgent(ec.ContainsStringMatch("curl")).
		WithRequestHost(ec.ContainsStringMatch("localhost:8282")).
		WithResponseVersion("HTTP/2").
		WithResponseReason("OK")

	// NOTE(JM): Not checking for process data due to issue #747
	// Process information unavailable as tuple.uid set to netns id
	// for local connections. It's set because otherwise the connection
	// tuple is not unique.
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewConnectEventChecker().
			HasDstPort(8282).
			End(),
		ec.NewHttpEventChecker().
			HasHttp(httpCh).
			End(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	go http2Server(ctx, 8282)

	if err := observer.WriteConfigFile(testConfigFile, httpConfig(8282)); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, obs, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "-v4", "--http2-prior-knowledge", "http://localhost:8282")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}
