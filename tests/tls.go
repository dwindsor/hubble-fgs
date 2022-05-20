package tests

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
)

func TlsChecker(kernelVersion string) ec.MultiResponseChecker {
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
		WithArguments("-4 https://google.com -m 30").
		WithPod(pod_checker)

	tls_checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curl_checker).
			HasParent(ec.NewProcessChecker().
				WithBinary(ec.ContainsStringMatch("runc")),
			).
			End(),
		ec.NewDNSEventChecker().
			HasProcess(curl_checker).
			HasDNS(ec.NewDNSChecker().
				WithAnswerTypes([]uint32{1}).
				WithNames([]ec.StringArg{"google.com."}).
				IsResponse(true),
			).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curl_checker).
			HasDstPort(443).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewTLSEventChecker().
			HasProcess(curl_checker).
			HasDstPort(443).
			HasNegotiatedVersion("TLS1.3").
			HasSupportedVersions([]string{"TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0"}).
			HasSniName("google.com").
			HasSniType("host_name").
			End(),
		ec.NewCloseEventChecker().
			HasProcess(curl_checker).
			HasDstPort(443).
			End(),
	)

	return tls_checker
}
