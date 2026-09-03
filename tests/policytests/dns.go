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
	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const dnsPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dns"
spec:
  parser:
    udp:
      enable: true
    dns:
      enable: true
      ports: [53]
`

var dnsCLIFlags = []policytest.CLIFlag{
	{Name: "enable-network-events", Value: true},
	{Name: "enable-udp", Value: true},
	{Name: "enable-udp-cgroup", Value: true},
	{Name: "enable-user-dns", Value: true},
	{Name: "dns-ports", Value: []int{53}},
}

func dnsPolicySkip(_ *policytest.SkipInfo) string {
	// TODO: add this info to agent info and
	// then use agent info istead of directly checking utils.CGroupSKBAvailable()
	if !utils.CGroupSKBAvailable() {
		return "test requires CGroup/SKB"
	}
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		return "test requires amd64 or kernel >=5.8"
	}
	return ""
}

func dnsCurlScenario(_ *policytest.Conf) *policytest.Scenario {
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	curl4Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-4 --max-time 10 https://www.google.com --next file:///dev/null"))
	curl6Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-6 --max-time 10 https://www.google.com --next file:///dev/null"))

	return &policytest.Scenario{
		Name: "resolve www.google.com over IPv4 and IPv6",
		// Bound the external transfer and end with a local one because only DNS matters.
		Trigger: policytest.NewMultiCmdTrigger([]policytest.CmdTrigger{
			{Bin: "/usr/bin/curl", Args: []string{"-4", "--max-time", "10", "https://www.google.com", "--next", "file:///dev/null"}},
			{Bin: "/usr/bin/curl", Args: []string{"-6", "--max-time", "10", "https://www.google.com", "--next", "file:///dev/null"}},
		}),
		EventChecker: ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("curl4Exec").WithProcess(curl4Checker).WithParent(selfChecker),
			ec.NewProcessConnectChecker("curl4Connect").
				WithProcess(curl4Checker).
				WithParent(selfChecker).
				WithDestinationPort(53).
				WithProtocol(tetragon.SocketProtocol_UDP),
			ec.NewProcessDnsChecker("curl4DnsReply").
				WithProcess(curl4Checker).
				WithParent(selfChecker).
				WithDns(ec.NewDnsInfoChecker().
					WithRcode(0).
					WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
					// TODO: remove this check at some point once we stop populating
					// Dns.QuestionTypes
					WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
					WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
					// TODO: remove this check at some point once we stop populating
					// Dns.AnswerTypes
					WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
					WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
					WithIps(ec.NewStringListMatcher().
						WithOperator(lm.Subset).
						// Match a valid IPv4 address
						WithValues(sm.Regex(`^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$`)))),
			ec.NewProcessExecChecker("curl6Exec").WithProcess(curl6Checker).WithParent(selfChecker),
			ec.NewProcessConnectChecker("curl6Connect").
				WithProcess(curl6Checker).
				WithParent(selfChecker).
				WithDestinationPort(53).
				WithProtocol(tetragon.SocketProtocol_UDP),
			ec.NewProcessDnsChecker("curl6DnsReply").
				WithProcess(curl6Checker).
				WithParent(selfChecker).
				WithDns(ec.NewDnsInfoChecker().
					WithRcode(0).
					WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
					// TODO: remove this check at some point once we stop populating
					// Dns.QuestionTypes
					WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(28)).
					WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
					// TODO: remove this check at some point once we stop populating
					// Dns.AnswerTypes
					WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(28)).
					WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
					WithIps(ec.NewStringListMatcher().
						WithOperator(lm.Subset).
						// Full IPv6 regex is probably too complicated, let's just see if it
						// contains a ::
						WithValues(sm.Contains(`::`)))),
		),
	}
}

var _ = policytest.NewBuilder("layer3-dns-curl").
	WithLabels("layer3", "dns").
	WithSkip(dnsPolicySkip).
	WithPolicyTemplate(dnsPolicy).
	AddScenario(dnsCurlScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-dns-curl-no-policy").
	WithLabels("layer3", "dns").
	WithCLIFlags(dnsCLIFlags...).
	WithSkip(dnsPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(dnsCurlScenario).
	RegisterAtInit()
