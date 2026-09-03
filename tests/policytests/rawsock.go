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
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/policytestconfig"
)

type rawsockTest int

const (
	noneNoneNone rawsockTest = iota
	packetRawLoop
	packetDgramIP
	inetRawUDP
	inetRawRaw
	packetRawAll
	packetDgramAll
)

func (test rawsockTest) String() string {
	switch test {
	case packetRawLoop:
		return "AF_PACKET SOCK_RAW ETH_P_LOOP"
	case packetDgramIP:
		return "AF_PACKET SOCK_DGRAM ETH_P_IP"
	case inetRawUDP:
		return "AF_INET SOCK_RAW IPPROTO_UDP"
	case inetRawRaw:
		return "AF_INET SOCK_RAW IPPROTO_RAW"
	case packetRawAll:
		return "AF_PACKET SOCK_RAW ETH_P_ALL"
	case packetDgramAll:
		return "AF_PACKET SOCK_DGRAM ETH_P_ALL"
	default:
		return "unknown"
	}
}

func rawsockPolicySkip(_ *policytest.SkipInfo) string {
	if !utils.RawHooksAvailable() {
		return "test requires raw socket support"
	}
	if !utils.CGroupSKBAvailable() {
		return "test requires CGroup/SKB"
	}
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		return "test requires amd64 or kernel >=5.8"
	}
	return ""
}

var rawsockPolicyBuilder = policytest.NewBuilder("layer3-rawsock-create-close").
	WithLabels("layer3", "rawsock").
	WithSkip(rawsockPolicySkip).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawsock"
spec:
  parser:
    rawsock:
      enable: true
      reportClose: true
`)

var rawsockCLIBuilder = policytest.NewBuilder("layer3-rawsock-create-close-no-policy").
	WithLabels("layer3", "rawsock").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-rawsock", Value: true},
		policytest.CLIFlag{Name: "rawsock-report-close", Value: true},
	).
	WithSkip(rawsockPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy)

func init() {
	for _, rawsockType := range []rawsockTest{
		packetRawLoop,
		packetDgramIP,
		inetRawUDP,
		inetRawRaw,
		packetRawAll,
		packetDgramAll,
	} {
		typeArgument := fmt.Sprintf("%d", rawsockType)
		scenario := func(_ *policytest.Conf) *policytest.Scenario {
			triggerPath := policytestconfig.EnterpriseTestBinary("net/rawsock")
			processChecker := ec.NewProcessChecker().
				WithBinary(sm.Suffix(filepath.Base(triggerPath))).
				WithArguments(sm.Full(typeArgument))
			return &policytest.Scenario{
				Name:    "raw socket " + rawsockType.String(),
				Trigger: policytest.NewCmdTrigger(triggerPath, typeArgument),
				EventChecker: ec.NewUnorderedEventChecker(
					ec.NewProcessExecChecker("rawsockExec").WithProcess(processChecker),
					ec.NewProcessRawsockCreateChecker("rawsockCreate").WithProcess(processChecker),
					ec.NewProcessRawsockCloseChecker("rawsockClose").
						WithProcess(processChecker).
						WithDuration(durationmatcher.Between(
							&durationmatcher.Duration{Duration: 0},
							&durationmatcher.Duration{Duration: 20 * time.Second},
						)),
				),
			}
		}
		rawsockPolicyBuilder.AddScenario(scenario)
		rawsockCLIBuilder.AddScenario(scenario)
	}
	rawsockPolicyBuilder.RegisterAtInit()
	rawsockCLIBuilder.RegisterAtInit()
}
