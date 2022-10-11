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

package httptls_test

import (
	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"

	"context"
	_ "embed"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	e2ehelpers "github.com/cilium/tetragon/tests/e2e/helpers"
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

const (
	namespace = "curl"
)

//go:embed curl.yaml
var curlYaml string

//go:embed http-tls-tracingpolicy.yaml
var tracingPolicyYaml string

func TestMain(m *testing.M) {
	runner = runners.NewRunner().WithInstallTetragon(install.WithHelmOptions(map[string]string{
		"enterprise.exportAllowList": "",
		"enterprise.enableTLSEvents": "true",
	})).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, cfg)
		ctx, err = helpers.CreateNamespace(namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create curl namespace: %w", err)
		}
		ctx, err = helpers.LoadCRDString(namespace, curlYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy curl pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.LoadCRDString(namespace, tracingPolicyYaml, true)(ctx, cfg)
		return ctx, nil
	})

	runner.Run(m)
}

func getCurlPod(ctx context.Context, client klient.Client) (*corev1.Pod, error) {
	r := client.Resources(namespace)

	podList := &corev1.PodList{}
	r.List(ctx, podList)

	if len(podList.Items) != 1 {
		return nil, fmt.Errorf("expected exactly 1 curl pod")
	}

	return &podList.Items[0], nil
}

func TestHttp(t *testing.T) {
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("5.10.0") {
		t.Skipf("HTTP and TLS tests need kernel >= 5.10, got %s", kversion)
	}

	httpChecker := checker.NewRPCChecker(HttpChecker(kversion), "httpChecker").WithEventLimit(1000).WithTimeLimit(2 * time.Minute)
	checkHttp := features.New("Check Http Events").
		Assess("Run Event Checks", httpChecker.CheckInNamespace(30*time.Second, "curl")).
		Feature()

	testHttp := features.New("Test Http").
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
			out, err := e2ehelpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"curl",
				strings.Fields("curl -4 http://google.com -m 30"))
			klog.Infof("curl output:\n%s", string(out))
			if !assert.NoError(t, err, "failed to run curl") {
				klog.Errorf("curl failed with error: %w", err)
				return ctx
			}

			return ctx
		}).
		Assess("Wait for events", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			time.Sleep(60 * time.Second)
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkHttp, testHttp)
}

func TestTls(t *testing.T) {
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("5.10.0") {
		t.Skipf("HTTP and TLS tests need kernel >= 5.10, got %s", kversion)
	}

	tlsChecker := checker.NewRPCChecker(TlsChecker(kversion), "tlsChecker").WithEventLimit(1000).WithTimeLimit(2 * time.Minute)
	checkTls := features.New("Check Tls Events").
		Assess("Run Event Checks", tlsChecker.CheckInNamespace(30*time.Second, "curl")).
		Feature()

	testTls := features.New("Test Tls").
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
			out, err := e2ehelpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"curl",
				strings.Fields("curl -4 https://google.com -m 30"))
			klog.Infof("curl output:\n%s", string(out))
			if !assert.NoError(t, err, "failed to run curl") {
				klog.Errorf("curl failed with error: %w", err)
				return ctx
			}

			return ctx
		}).
		Assess("Wait for events", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			time.Sleep(60 * time.Second)
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkTls, testTls)
}

func TlsChecker(kernelVersion string) ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("curl")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/curlimages/curl:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("curl")).
		WithName(sm.Prefix("curl")).
		WithLabels(map[string]sm.StringMatcher{
			"k8s:app":                                 *sm.Full("curl"),
			"k8s:io.cilium.k8s.policy.cluster":        *sm.Contains(helpers.GetClusterName()),
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
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker().
			WithProcess(curlChecker).
			WithDestinationPort(443),
	)

	// It's still worth running the other checks here even if TLS is not supported
	if kernels.KernelStringToNumeric(kernelVersion) < kernels.KernelStringToNumeric("5.10.0") {
		klog.Info("TLS events need kernel >= 5.10, skipping TLS checks")
	} else {
		tlsChecker.AddChecks(ec.NewTlsChecker().
			WithProcess(curlChecker).
			WithDestinationPort(443).
			WithNegotiatedVersion(sm.Full("TLS1.3")).
			WithSupportedVersions(sm.Full("TLS1.3 TLS1.2 TLS1.1 TLS1.0")).
			WithSniName(sm.Contains("google.com")).
			WithSniType(sm.Full("host_name")),
		)
	}

	return tlsChecker
}

func HttpChecker(kernelVersion string) ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("curl")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/curlimages/curl:latest")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("curl")).
		WithName(sm.Prefix("curl")).
		WithLabels(map[string]sm.StringMatcher{
			"k8s:app":                                 *sm.Full("curl"),
			"k8s:io.cilium.k8s.policy.cluster":        *sm.Contains(helpers.GetClusterName()),
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
