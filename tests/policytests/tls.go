// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

type tlsCurlTrigger struct {
	retries uint
	args    []string
}

func (trigger *tlsCurlTrigger) Trigger(_ context.Context) error {
	var readyWG sync.WaitGroup
	return observertesthelper.ExecWGCurl(&readyWG, trigger.retries, trigger.args...)
}

var tlsConfig = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "{{ .mode }}"
      selectors:
      - matchPorts:
        - 443
    tcp:
      enable: true
`

var curlPath = "/usr/bin/curl"

var selfChecker = ec.NewProcessChecker().
	WithBinary(sm.Suffix(filepath.Base(os.Args[0])))

var curlChecker = ec.NewProcessChecker().
	WithBinary(sm.Suffix(filepath.Base(curlPath))).
	WithArguments(sm.Full("--tlsv1.3 --curves X25519 -4 https://www.google.com"))

var tlsChecker = ec.NewTlsChecker("curlTls").
	WithProcess(curlChecker).
	WithParent(selfChecker).
	WithNegotiatedVersion(sm.Full("TLS1.3")).
	WithClientVersion(sm.Full("TLS1.2")).
	WithServerVersion(sm.Full("TLS1.2")).
	WithSniType(sm.Full("host_name")).
	WithSniName(sm.Contains("www.google.com")).
	WithClientFlags(sm.Contains("ExtVersion")).
	WithServerFlags(sm.Contains("ExtVersion"))

var checker = ec.NewUnorderedEventChecker(
	ec.NewProcessExecChecker("curlExec").
		WithProcess(curlChecker).
		WithParent(selfChecker),
	ec.NewProcessConnectChecker("curlConnect").
		WithProcess(curlChecker).
		WithParent(selfChecker).
		WithDestinationPort(443),
	tlsChecker,
)

func tlsPolicySkip(_ *policytest.SkipInfo) string {
	if version := "5.10.0"; !kernels.MinKernelVersion(version) {
		return fmt.Sprintf("minimum kernel version %s not met", version)
	}
	if runtime.GOARCH != "amd64" {
		return "ARM bug breaks mixed bpf2bpf calls and tail calls"
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		return "skipping on flaky HTTP kernel"
	}
	return ""
}

var tls13CurlTrigger = tlsCurlTrigger{
	retries: 10,
	args:    []string{"--tlsv1.3", "--curves", "X25519", "-4", "https://www.google.com"},
}

var _ = policytest.NewBuilder("tls-13-curl-policy").
	WithLabels("tls").
	WithParameter(policytest.Parameter{
		Name:    "mode",
		Default: "socket",
		Values:  []any{"socket", "cgroup"},
		Help:    "mode for the TLS parser"}).
	WithSkip(tlsPolicySkip).
	WithPolicyTemplate(tlsConfig).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		return &policytest.Scenario{
			Name:         "curl negotiates TLS 1.3 via policy",
			Trigger:      &tls13CurlTrigger,
			EventChecker: checker,
		}
	}).
	RegisterAtInit()

var _ = policytest.NewBuilder("tls-13-curl-no-policy-socket").
	WithLabels("tls").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-udp-cgroup", Value: true},
		policytest.CLIFlag{Name: "enable-user-dns", Value: true},
		policytest.CLIFlag{Name: "dns-ports", Value: []int{53}},
		policytest.CLIFlag{Name: "enable-tcp", Value: true},
		policytest.CLIFlag{Name: "enable-tls-sensor", Value: true},
		policytest.CLIFlag{Name: "tls-sensor-mode", Value: "socket"},
		policytest.CLIFlag{Name: "tls-sensor-ports", Value: []int{443}},
	).
	WithSkip(tlsPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		return &policytest.Scenario{
			Name:         "curl negotiates TLS 1.3 via CLI",
			Trigger:      &tls13CurlTrigger,
			EventChecker: checker,
		}
	}).
	RegisterAtInit()

var _ = policytest.NewBuilder("tls-13-curl-no-policy-cgroup").
	WithLabels("tls").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-udp-cgroup", Value: true},
		policytest.CLIFlag{Name: "enable-user-dns", Value: true},
		policytest.CLIFlag{Name: "dns-ports", Value: []int{53}},
		policytest.CLIFlag{Name: "enable-tcp", Value: true},
		policytest.CLIFlag{Name: "enable-tls-sensor", Value: true},
		policytest.CLIFlag{Name: "tls-sensor-mode", Value: "cgroup"},
		policytest.CLIFlag{Name: "tls-sensor-ports", Value: []int{443}},
	).
	WithSkip(tlsPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		return &policytest.Scenario{
			Name:         "curl negotiates TLS 1.3 via CLI",
			Trigger:      &tls13CurlTrigger,
			EventChecker: checker,
		}
	}).
	RegisterAtInit()
