package tests

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
)

func TlsChecker(kernelVersion string) ec.MultiEventChecker {
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
		WithArguments(sm.Full("-4 https://google.com -m 30")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("runc"))

	tlsChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(shellChecker),
		ec.NewProcessDnsChecker().
			WithProcess(curlChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Contains("google.com"))).
				WithResponse(true),
			),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithDestinationPort(443).
			WithProtocol(fgs.SocketProtocol_TCP),
		ec.NewTlsChecker().
			WithProcess(curlChecker).
			WithDestinationPort(443).
			WithNegotiatedVersion(sm.Full("TLS1.3")).
			WithSupportedVersions(sm.Full("TLS1.3 TLS1.2 TLS1.1 TLS1.0")).
			WithSniName(sm.Contains("google.com")).
			WithSniType(sm.Full("host_name")),
		ec.NewProcessCloseChecker().
			WithProcess(curlChecker).
			WithDestinationPort(443),
	)

	return tlsChecker
}
