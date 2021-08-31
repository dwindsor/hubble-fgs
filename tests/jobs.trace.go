package main

import (
	"fmt"
	"os"

	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/observer"

	"github.com/sirupsen/logrus"
)

var (
	jc = ec.NewPodChecker().
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

	checker = ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasParent(ec.NewProcessChecker().
				WithBinary("/bin/sh").
				WithArguments("-c \"PORT=9080 node server.js\"").
				WithPod(jc)).
			HasAncestor(0, ec.NewProcessChecker().
				WithBinary("/usr/local/bin/docker-entrypoint.sh").
				WithArguments("/usr/local/bin/docker-entrypoint.sh /bin/sh -c \"PORT=9080 node server.js\"").
				WithPod(jc)).
			HasAncestor(1, ec.NewProcessChecker().
				WithBinary("/usr/bin/containerd-shim-runc-v2"),
			).End(),
		ec.NewConnectEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js")).
			HasDstPort(9080).
			End(),
	)
)

func main() {
	jsonFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Errorf("🔥 opening json file failed: %w", err)
		os.Exit(1)
	}
	logger := ec.LogrusLogger{logrus.New()}
	err = observer.JsonCheck(jsonFile, &checker, &logger)
	if err != nil {
		fmt.Printf("🔥 Failed: no dice: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("🚢 Passed: ship it\n")
	os.Exit(0)
}
