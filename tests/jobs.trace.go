package main

import (
	"fmt"
	"os"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
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
)

func test_demo_app_end_to_end(file *os.File, log ec.Logger, is_gke bool) error {
	file.Seek(0, 0)

	demo_checker := ec.NewUnorderedMultiResponseChecker(
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
			HasAncestor(1, ec.NewProcessCheckerOr().
				With(ec.NewProcessChecker().
					WithBinary("/usr/bin/containerd-shim-runc-v2")).
				With(ec.NewProcessChecker().
					WithBinary("/usr/local/bin/containerd-shim-runc-v2")),
			).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasDstPort(9080).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasPort(9080).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasSrcPort(9080).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasDstPort(9080).
			End(),
	)

	if err := observer.JsonCheck(file, demo_checker, log); err != nil {
		return err
	}

	if !is_gke {
		dns_checker := ec.NewUnorderedMultiResponseChecker(ec.NewDnsEventChecker().
			HasProcess(ec.NewProcessChecker().
				WithBinary("/usr/local/bin/node").
				WithArguments("server.js").
				WithPod(jc)).
			HasDns(ec.NewDnsChecker().
				WithAnswerTypes([]uint32{1}).
				WithNames([]ec.StringArg{"coreapi.tenant-jobs.svc.cluster.local."}).
				IsResponse(true),
			).
			End())

		file.Seek(0, 0)
		if err := observer.JsonCheck(file, dns_checker, log); err != nil {
			return err
		}
	}

	return nil
}

func test_tls_end_to_end(file *os.File, log ec.Logger) error {
	file.Seek(0, 0)

	curl_checker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("curl")).
		WithArguments("-4 https://google.com -m 30").
		WithPod(jc)
	tls_checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().HasProcess(curl_checker).
			HasAncestor(0, ec.NewProcessChecker().
				WithBinary(ec.SuffixStringMatch("containerd-shim-runc-v2")),
			).
			HasAncestor(1, ec.NewProcessChecker().
				WithBinary(ec.SuffixStringMatch("containerd-shim-runc-v2")),
			).
			End(),
		ec.NewDnsEventChecker().
			HasProcess(curl_checker).
			HasDns(ec.NewDnsChecker().
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
		ec.NewTlsEventChecker().
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

	if err := observer.JsonCheck(file, tls_checker, log); err != nil {
		return err
	}

	return nil
}

func test_http_end_to_end(file *os.File, log ec.Logger) error {
	curl_checker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("curl")).
		WithArguments("-4 http://google.com -m 30").
		WithPod(jc)

	http_checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(curl_checker).
			HasAncestor(0, ec.NewProcessChecker().
				WithBinary(ec.SuffixStringMatch("containerd-shim-runc-v2")),
			).
			HasAncestor(1, ec.NewProcessChecker().
				WithBinary(ec.SuffixStringMatch("containerd-shim-runc-v2")),
			).
			End(),
		ec.NewHttpEventChecker().
			HasProcess(curl_checker).
			HasHttp(ec.NewHttpChecker().
				WithRequestAgent(ec.ContainsStringMatch("curl")).
				WithRequestHost("google.com").
				WithRequestVersion("HTTP/1.1").
				WithRequestMethod("GET").
				WithRequestUri("/").
				WithResponseVersion("HTTP/1.1").
				WithResponseReason("Moved Permanently").
				WithResponseCode(301),
			).
			End(),
	)

	file.Seek(0, 0)
	if err := observer.JsonCheck(file, &http_checker, log); err != nil {
		return err
	}

	return nil
}

func main() {
	logger := ec.LogrusLogger{L: logrus.New()}
	is_gke := false

	if len(os.Args) >= 3 {
		if os.Args[2] == "gke" {
			fmt.Println("Running in GKE, skipping some tests...")
			is_gke = true
		}
	}

	jsonFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("🔥 opening json file failed: %s", err)
		os.Exit(1)
	}

	if err := test_demo_app_end_to_end(jsonFile, &logger, is_gke); err != nil {
		fmt.Printf("🔥 Demo app check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	// Tests below this line won't be run in GKE ----------------------
	if is_gke {
		return
	}

	if err := test_tls_end_to_end(jsonFile, &logger); err != nil {
		fmt.Printf("🔥 TLS check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	if err := test_http_end_to_end(jsonFile, &logger); err != nil {
		fmt.Printf("🔥 HTTP check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚢 Passed: ship it\n")
	os.Exit(0)
}
