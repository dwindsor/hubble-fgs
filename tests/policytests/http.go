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
	"os/exec"
	"path/filepath"
	"runtime"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// This file contains policy tests for the HTTP parser.

// curlTrigger runs curl against a URL, retrying on failure since the test relies on
// reaching a live external endpoint (www.google.com).
type curlTrigger struct {
	args    []string
	retries int
}

func newCurlTrigger(retries int, args ...string) *curlTrigger {
	return &curlTrigger{args: args, retries: retries}
}

func (c *curlTrigger) Trigger(ctx context.Context) error {
	var err error
	for try := 0; try <= c.retries; try++ {
		if err = exec.CommandContext(ctx, "/usr/bin/curl", c.args...).Run(); err == nil {
			return nil
		}
	}
	return err
}

func httpPolicySkip(_ *policytest.SkipInfo) string {
	// TODO: These checks are run locally, but they should come from agent info. We want to eventually be able to
	// run "tetra policytests" on a different host than the agent under test.
	if v := "6.1.56"; !kernels.MinKernelVersion(v) {
		return fmt.Sprintf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		return "ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping"
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		return "Skipping test on flaky kernel"
	}
	return ""
}

func http11CurlScenario(_ *policytest.Conf) *policytest.Scenario {
	// TODO: In the future, the trigger will be run on the agent host, instead of locally. When this happens,
	// filepath.Base(os.Args[0]) will need to be replaced with the path of tetragon on the agent-under-test's host.
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(filepath.Base(os.Args[0])))

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

	return &policytest.Scenario{
		Name: "curl http://www.google.com over ipv4",
		// TODO: In the future, the trigger will be run on the agent-under-test's host, instead of locally.
		// When we make that change, we will have to change how this trigger works
		Trigger: newCurlTrigger(10, "-4", "http://www.google.com"),
		EventChecker: ec.NewUnorderedEventChecker(
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
		),
	}
}

var _ = policytest.NewBuilder("http-11-curl").
	WithLabels("http").
	WithSkip(httpPolicySkip).
	WithPolicyTemplate(`
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
        - 80
    tcp:
      enable: true
`).
	AddScenario(http11CurlScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("http-11-curl-no-policy").
	WithLabels("http").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-udp-cgroup", Value: true},
		policytest.CLIFlag{Name: "enable-user-dns", Value: true},
		policytest.CLIFlag{Name: "dns-ports", Value: []int{53}},
		policytest.CLIFlag{Name: "enable-tcp", Value: true},
		policytest.CLIFlag{Name: "enable-http-sensor", Value: true},
		policytest.CLIFlag{Name: "http-sensor-ports", Value: []int{80}},
	).
	WithSkip(httpPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(http11CurlScenario).
	RegisterAtInit()
