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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/observer"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"

	"github.com/stretchr/testify/assert"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int
)

const (
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")

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

var (
	tlstc = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "tc"
    tcp:
      enable: true
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

	tlsCh := ec.NewTLSChecker().
		WithNegotiatedVersion("TLS1.3").
		WithClientVersion("TLS1.2").
		WithServerVersion("TLS1.2").
		WithSniType("host_name").
		WithSniName("www.google.com").
		WithClientFlags("ExtVersion").
		WithServerFlags("ExtVersion")

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(443).
			End(),
		ec.NewTLSEventChecker().
			HasProcess(curlChecker).
			HasTLS(tlsCh).
			End(),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "--tlsv1.3", "-4", "https://www.google.com")

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTCTLS12(t *testing.T) {
	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("--tlsv1.2 --tls-max 1.2 -4 https://www.google.com/"),
	)
	tlsCh := ec.NewTLSChecker().
		WithClientVersion("TLS1.2").
		WithServerVersion("TLS1.2").
		WithSniType("host_name").
		WithSniName("www.google.com").
		WithClientFlags("").
		WithServerFlags("").
		WithCertificates([]ec.StringArg{
			"CN=www.google.com",
			"CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
			"CN=GTS Root R1,O=Google Trust Services LLC,C=US",
		})

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstPort(443).
			End(),
		ec.NewTLSEventChecker().
			HasProcess(curlChecker).
			HasTLS(tlsCh).
			End(),
	)

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "--tlsv1.2", "--tls-max", "1.2", "-4", "https://www.google.com/")

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
