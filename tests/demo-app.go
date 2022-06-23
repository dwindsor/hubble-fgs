package tests

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	ec "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker"
)

func DemoAppChecker(kernelVersion string) ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("jobposting")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("quay.io/isovalent/jobs-app-jobposting:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("tenant-jobs")).
		WithName(sm.Prefix("jobposting")).
		WithLabels(map[string]sm.StringMatcher{
			"k8s:app":                                 *sm.Full("jobposting"),
			"k8s:io.cilium.k8s.policy.cluster":        *sm.Prefix("fgs-cli-ci"),
			"k8s:io.cilium.k8s.policy.serviceaccount": *sm.Full("default"),
			"k8s:io.kubernetes.pod.namespace":         *sm.Full("tenant-jobs"),
		}).
		WithContainer(containerChecker)

	nodeJsChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/node")).
		WithArguments(sm.Contains("server.js")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/sh")).
		WithArguments(sm.Full("-c \"PORT=9080 node server.js\""))

	demoAppChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(nodeJsChecker).
			WithParent(shellChecker),
		ec.NewProcessConnectChecker().
			WithProcess(nodeJsChecker).
			WithDestinationPort(9080),
		ec.NewProcessListenChecker().
			WithProcess(nodeJsChecker).
			WithPort(9080),
		ec.NewProcessAcceptChecker().
			WithProcess(nodeJsChecker).
			WithSourcePort(9080),
		ec.NewProcessCloseChecker().
			WithProcess(nodeJsChecker).
			WithDestinationPort(9080),
	)

	if kernels.KernelStringToNumeric(kernelVersion) >= kernels.KernelStringToNumeric("5.10.0") {
		dnsChecker := ec.NewDnsInfoChecker().
			WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
			WithNames(ec.NewStringListMatcher().WithValues(sm.Full("coreapi.tenant-jobs.svc.cluster.local."))).
			WithResponse(true)

		dnsEventChecker := ec.NewProcessDnsChecker().
			WithProcess(nodeJsChecker).
			WithDns(dnsChecker)

		demoAppChecker.AddChecks(dnsEventChecker)
	} else {
		fmt.Printf("Skipping DNS checks due to insufficienct kernel version (needs 5.10.0+, got %s)\n", kernelVersion)
	}

	return demoAppChecker
}
