//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package httptls

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	Namespace = "curl"
)

//go:embed curl.yaml
var CURLYAML string

//go:embed http-tls-tracingpolicy.yaml
var TracingPolicyYAML string

func TestHTTP(t *testing.T, runner *runners.Runner) {
	// Must be called at the beginning of every test
	runner.SetupExport(t)

	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("5.10.0") {
		t.Skipf("HTTP and TLS tests need kernel >= 5.10, got %s", kversion)
	}

	httpChecker := checker.NewRPCChecker(HTTPChecker(kversion), "hTTPChecker").WithEventLimit(1000).WithTimeLimit(3 * time.Minute)
	checkHTTP := features.New("Check Http Events").
		Assess("Run Event Checks", httpChecker.CheckInNamespace(30*time.Second, "curl")).
		Feature()

	testHTTP := features.New("Test Http").
		Assess("Wait For Checker", httpChecker.Wait(30*time.Second)).
		Assess("Run Curl Workload", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if !assert.NoError(t, err, "unable to get kube client") {
				return ctx
			}
			pod, err := getCurlPod(ctx, client)
			if !assert.NoError(t, err, "unable to get curl pod") {
				return ctx
			}
			out, err := helpers.ExecInPodCombinedOutput(ctx,
				client,
				Namespace,
				pod.Name,
				"curl",
				strings.Fields("curl -4 http://google.com -m 30"))
			klog.Infof("curl output:\n%s", string(out))
			if !assert.NoError(t, err, "failed to run curl") {
				klog.Errorf("curl failed with error: %s", err)
				return ctx
			}

			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkHTTP, testHTTP)
}

func TestTLS(t *testing.T, runner *runners.Runner) {
	// Must be called at the beginning of every test
	runner.SetupExport(t)

	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("5.10.0") {
		t.Skipf("HTTP and TLS tests need kernel >= 5.10, got %s", kversion)
	}

	tlsChecker := checker.NewRPCChecker(TLSChecker(kversion), "tLSChecker").WithEventLimit(1000).WithTimeLimit(3 * time.Minute)
	checkTls := features.New("Check TLS Events").
		Assess("Run Event Checks", tlsChecker.CheckInNamespace(30*time.Second, "curl")).
		Feature()

	testTls := features.New("Test TLS").
		Assess("Wait For Checker", tlsChecker.Wait(30*time.Second)).
		Assess("Run Curl Workload", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if !assert.NoError(t, err, "unable to get kube client") {
				return ctx
			}
			pod, err := getCurlPod(ctx, client)
			if !assert.NoError(t, err, "unable to get curl pod") {
				return ctx
			}
			out, err := helpers.ExecInPodCombinedOutput(ctx,
				client,
				Namespace,
				pod.Name,
				"curl",
				strings.Fields("curl -4 https://google.com -m 30"))
			klog.Infof("curl output:\n%s", string(out))
			if !assert.NoError(t, err, "failed to run curl") {
				klog.Errorf("curl failed with error: %s", err)
				return ctx
			}

			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkTls, testTls)
}

func TLSChecker(_ string) ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("curl")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/curlimages/curl:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("curl")).
		WithName(sm.Prefix("curl")).
		WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("curl"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}).
		WithContainer(containerChecker)

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/curl")).
		WithArguments(sm.Full("-4 https://google.com -m 30")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("runc"))

	tlsChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(shellChecker),
		ec.NewProcessDnsChecker("curlDns").
			WithProcess(curlChecker).
			WithDns(ec.NewDnsInfoChecker().
				// TODO: remove this check at some point once we stop populating
				// Dns.AnswerTypes
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Contains("google.com"))).
				WithReturnCode(0).
				WithResponse(true),
			),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithDestinationPort(443).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("curlClose").
			WithProcess(curlChecker).
			WithDestinationPort(443),
		ec.NewTlsChecker("curlTls").
			WithProcess(curlChecker).
			WithDestinationPort(443).
			WithNegotiatedVersion(sm.Full("TLS1.3")).
			WithSupportedVersions(sm.Full("TLS1.3 TLS1.2")).
			WithSniName(sm.Contains("google.com")).
			WithSniType(sm.Full("host_name")),
	)

	return tlsChecker
}

func HTTPChecker(_ string) ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("curl")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/curlimages/curl:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("curl")).
		WithName(sm.Prefix("curl")).
		WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("curl"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
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
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(shellChecker),
		ec.NewProcessHttpChecker("curlHTTP").
			WithProcess(curlChecker).
			WithHttp(httpEventChecker),
	)

	return httpChecker
}

func getCurlPod(ctx context.Context, client klient.Client) (*corev1.Pod, error) {
	r := client.Resources(Namespace)

	podList := &corev1.PodList{}
	r.List(ctx, podList)

	if len(podList.Items) != 1 {
		return nil, fmt.Errorf("expected exactly 1 curl pod")
	}

	return &podList.Items[0], nil
}
