package tests

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
)

func HttpChecker(kernelVersion string) ec.MultiResponseChecker {
	if kernels.KernelStringToNumeric(kernelVersion) < kernels.KernelStringToNumeric("5.10.0") {
		fmt.Printf("Skipping all checks due to insufficienct kernel version (needs 5.10.0+, got %s)\n", kernelVersion)
		return ec.NewUnorderedMultiResponseChecker()
	}

	pod_checker := ec.NewPodChecker().
		WithNamespace("curl").
		WithNamePrefix("curl").
		WithLabels(
			ec.LabelMatchVal("k8s:app", "curl"),
			ec.LabelMatchValPrefix("k8s:io.cilium.k8s.policy.cluster", "fgs-cli-ci"),
			ec.LabelMatchVal("k8s:io.cilium.k8s.policy.serviceaccount", "default"),
			ec.LabelMatchVal("k8s:io.kubernetes.pod.namespace", "curl"),
		).
		WithContainer(ec.NewContainerChecker().
			WithName("curl").
			WithImageName("docker.io/curlimages/curl:latest"),
		)

	curl_checker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("curl")).
		WithArguments("-4 http://google.com -m 30").
		WithPod(pod_checker)

	http_checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curl_checker).
			HasParent(ec.NewProcessChecker().
				WithBinary(ec.ContainsStringMatch("runc")),
			).
			End(),
		ec.NewHTTPEventChecker().
			HasProcess(curl_checker).
			HasHTTP(ec.NewHTTPChecker().
				WithRequestAgent(ec.ContainsStringMatch("curl")).
				WithRequestHost("google.com").
				WithRequestVersion("HTTP/1.1").
				WithRequestMethod("GET").
				WithRequestURI("/").
				WithResponseVersion("HTTP/1.1").
				WithResponseReason("Moved Permanently").
				WithResponseCode(301),
			).
			End(),
	)

	return http_checker
}
