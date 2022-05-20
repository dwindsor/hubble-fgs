package tests

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
)

func DemoAppChecker(kernelVersion string) ec.MultiResponseChecker {
	pod_checker := ec.NewPodChecker().
		WithNamespace("tenant-jobs").
		WithNamePrefix("jobposting").
		WithLabels(
			ec.LabelMatchVal("k8s:app", "jobposting"),
			ec.LabelMatchValPrefix("k8s:io.cilium.k8s.policy.cluster", "fgs-cli-ci"),
			ec.LabelMatchVal("k8s:io.cilium.k8s.policy.serviceaccount", "default"),
			ec.LabelMatchVal("k8s:io.kubernetes.pod.namespace", "tenant-jobs"),
		).
		WithContainer(ec.NewContainerChecker().
			WithName("jobposting").
			WithImageName("quay.io/isovalent/jobs-app-jobposting:latest"),
		)

	nodejs_checker := ec.NewProcessChecker().
		WithBinary("/usr/local/bin/node").
		WithArguments("server.js").
		WithPod(pod_checker)

	demo_app_checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(nodejs_checker).
			HasParent(ec.NewProcessChecker().
				WithBinary("/bin/sh").
				WithArguments("-c \"PORT=9080 node server.js\"")).
			HasAncestor(0, ec.NewProcessChecker().
				WithBinary("/usr/local/bin/docker-entrypoint.sh").
				WithArguments("/usr/local/bin/docker-entrypoint.sh /bin/sh -c \"PORT=9080 node server.js\"")).
			HasAncestor(1, ec.NewProcessCheckerOr().
				With(ec.NewProcessChecker().
					WithBinary("/usr/bin/containerd-shim-runc-v2")).
				With(ec.NewProcessChecker().
					WithBinary("/usr/local/bin/containerd-shim-runc-v2")),
			).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(nodejs_checker).
			HasDstPort(9080).
			End(),
		ec.NewListenEventChecker().
			HasProcess(nodejs_checker).
			HasPort(9080).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(nodejs_checker).
			HasSrcPort(9080).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(nodejs_checker).
			HasDstPort(9080).
			End(),
	)

	if kernels.KernelStringToNumeric(kernelVersion) >= kernels.KernelStringToNumeric("5.10.0") {
		demo_app_checker.Append(ec.NewDNSEventChecker().
			HasProcess(nodejs_checker).
			HasDNS(ec.NewDNSChecker().
				WithAnswerTypes([]uint32{1}).
				WithNames([]ec.StringArg{"coreapi.tenant-jobs.svc.cluster.local."}).
				IsResponse(true),
			).
			End())
	} else {
		fmt.Printf("Skipping DNS checks due to insufficienct kernel version (needs 5.10.0+, got %s)\n", kernelVersion)
	}

	return demo_app_checker
}
