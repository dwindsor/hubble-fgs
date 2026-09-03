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
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func icmpPolicySkip(_ *policytest.SkipInfo) string {
	// TODO: Determine this from agent info
	if !utils.CGroupSKBAvailable() {
		return "test requires CGroup/SKB"
	}
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		return "test requires amd64 or kernel >=5.8"
	}
	return ""
}

func icmpPingScenario(_ *policytest.Conf) *policytest.Scenario {
	const triggerPath = "/usr/bin/ping"
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(filepath.Base(triggerPath))).
		WithArguments(sm.Full("-c1 127.0.0.1"))

	return &policytest.Scenario{
		Name:    "ping localhost over IPv4",
		Trigger: policytest.NewCmdTrigger(triggerPath, "-c1", "127.0.0.1"),
		EventChecker: ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("pingExec").WithProcess(pingChecker).WithParent(selfChecker),
			ec.NewProcessIcmpChecker("pingEcho").
				WithProcess(pingChecker).
				WithParent(selfChecker).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithProtocol(tetragon.SocketProtocol_ICMP).
				WithIcmpType(sm.Full("Echo")).
				WithSequenceNumber(1).
				WithIcmpDataLen(56).
				WithDirection(sm.Full("egress")),
			ec.NewProcessIcmpChecker("pingEchoReply").
				WithProcess(pingChecker).
				WithParent(selfChecker).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithProtocol(tetragon.SocketProtocol_ICMP).
				WithIcmpType(sm.Full("Echo Reply")).
				WithSequenceNumber(1).
				WithIcmpDataLen(56).
				WithDirection(sm.Full("ingress")),
		),
	}
}

var _ = policytest.NewBuilder("layer3-icmp-ping").
	WithLabels("layer3", "icmp").
	WithSkip(icmpPolicySkip).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "icmp"
spec:
  parser:
    icmp:
      enable: true
`).
	AddScenario(icmpPingScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-icmp-ping-no-policy").
	WithLabels("layer3", "icmp").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-network-events", Value: true},
		policytest.CLIFlag{Name: "enable-icmp", Value: true},
	).
	WithSkip(icmpPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(icmpPingScenario).
	RegisterAtInit()
