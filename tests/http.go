package tests

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	ec "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker"
	sm "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker/matchers/stringmatcher"
)

func HttpChecker(kernelVersion string) ec.MultiEventChecker {
	if kernels.KernelStringToNumeric(kernelVersion) < kernels.KernelStringToNumeric("5.10.0") {
		fmt.Printf("Skipping all checks due to insufficienct kernel version (needs 5.10.0+, got %s)\n", kernelVersion)
		return ec.NewUnorderedEventChecker()
	}

	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("curl")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/curlimages/curl:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("curl")).
		WithName(sm.Prefix("curl")).
		WithLabels(map[string]sm.StringMatcher{
			"k8s:app":                                 *sm.Full("curl"),
			"k8s:io.cilium.k8s.policy.cluster":        *sm.Prefix("fgs-cli-ci"),
			"k8s:io.cilium.k8s.policy.serviceaccount": *sm.Full("default"),
			"k8s:io.kubernetes.pod.namespace":         *sm.Full("curl"),
		}).
		WithContainer(containerChecker)

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/curl")).
		WithArguments(sm.Full("-4 http://google.com -m 30")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("runc"))

	httpEventChecker := ec.NewHttpInfoChecker().
		WithRequest(ec.NewHttpRequestChecker().
			WithAgent(sm.Contains("curl")).
			WithHost(sm.Contains("google.com")).
			WithVersion(sm.Full("HTTP/1.1")).
			WithMethod(sm.Full("GET")).
			WithUri(sm.Full("/")),
		).
		WithResponse(ec.NewHttpResponseChecker().
			WithVersion(sm.Full("HTTP/1.1")).
			WithReason(sm.Full("Moved Permanently")).
			WithCode(301),
		)

	httpChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(shellChecker),
		ec.NewProcessHttpChecker().
			WithProcess(curlChecker).
			WithHttp(httpEventChecker),
	)

	return httpChecker
}
