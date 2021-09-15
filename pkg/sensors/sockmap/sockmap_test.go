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

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	curlTLSEvent = &fgs.GetEventsResponse_Tls{
		Tls: &fgs.Tls{
			Process: &fgs.Process{
				Binary:    "curl",
				Arguments: "https://google.com"},
			NegotiatedVersion: "TLS1.3",
			ClientVersion:     "TLS 1.2",
			ServerVersion:     "TLS 1.2",
			SniType:           "host_name",
			SniName:           "www.google.com",
			ClientFlags:       "ExtVersion",
			ServerFlags:       "ExtVersion",
		},
	}

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

	traceTCTLS13 := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					DestinationPort: &wrapperspb.UInt32Value{Value: 443},
				},
			},
		},
		&fgs.GetEventsResponse{Event: curlTLSEvent},
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kprobe, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "https://www.google.com")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, kprobe)
}

func TestTCTLS12(t *testing.T) {
	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	certs := []string{
		"CN=*.badssl.com,O=Lucas Garron Torres,L=Walnut Creek,ST=California,C=US",
		"CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
	}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					DestinationPort: &wrapperspb.UInt32Value{Value: 1012},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Tls{
				Tls: &fgs.Tls{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					DestinationPort: &wrapperspb.UInt32Value{Value: 1012},
					ClientVersion:   "TLS 1.2",
					ServerVersion:   "TLS 1.2",
					SniType:         "host_name",
					SniName:         "tls-v1-2.badssl.com",
					ClientFlags:     "ExtVersion",
					ServerFlags:     "",
					Certificates:    certs,
				},
			},
		},
	}

	if err := observer.WriteConfigFile(testConfigFile, tlstc); err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	kprobe, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	observer.ExecWGCurl(&execWG, &exitWG, "https://tls-v1-2.badssl.com:1012/")

	err = observer.JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observer.TestDone(t, kprobe)
}
