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

package demoapp_test

import (
	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"

	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

const (
	namespace = "demo-app"
)

//go:embed demo-app-tracingpolicy.yaml
var tracingPolicyYaml string

func installDemoApp() features.Func {
	return func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
		manager := helm.New(c.KubeconfigFile())
		if err := manager.RunRepo(helm.WithArgs("add", "isovalent", "https://helm.isovalent.com")); err != nil {
			t.Fatalf("failed to add helm repo: %s", err)
		}

		if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
			t.Fatalf("failed to update helm repo: %s", err)
		}

		if err := manager.RunInstall(
			helm.WithName("jobs-app"),
			helm.WithChart("isovalent/jobs-app"),
			helm.WithVersion("v0.1.1"),
			helm.WithNamespace(namespace),
			helm.WithArgs("--create-namespace"),
		); err != nil {
			t.Fatalf("failed to install demo app. run with `-args -v=4` for more context from helm: %s", err)
		}

		return ctx
	}
}

func uninstallDemoApp() features.Func {
	return func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
		manager := helm.New(c.KubeconfigFile())
		if err := manager.RunUninstall(
			helm.WithName("jobs-app"),
			helm.WithNamespace(namespace),
		); err != nil {
			t.Fatalf("failed to uninstall demo app. run with `-args -v=4` for more context from helm: %s", err)
		}
		return ctx
	}
}

func TestMain(m *testing.M) {
	runner = runners.NewRunner().Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.LoadCRDString(namespace, tracingPolicyYaml, true)(ctx, cfg)
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, cfg)
		ctx, err := helpers.CreateNamespace(namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create demo app namespace: %w", err)
		}

		return ctx, nil
	})

	runner.Run(m)
}

func TestDemoApp(t *testing.T) {
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	demoChecker := checker.NewRPCChecker(DemoAppChecker(kversion), "demoChecker").WithTimeLimit(5 * time.Minute)
	testDemoApp := features.New("Test Demo App").
		Assess("Run Event Checks", demoChecker.CheckInNamespace(30*time.Second, "demo-app")).
		Feature()

	run := features.New("Setup Demo App").
		Assess("Wait For Checker", demoChecker.Wait(30*time.Second)).
		Assess("Run Workload", installDemoApp()).
		Assess("Wait for events", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			time.Sleep(60 * time.Second)
			return ctx
		}).
		Feature()

	cleanup := features.New("Cleanup").
		Assess("Uninstall Demo App", uninstallDemoApp()).
		Feature()

	runner.TestInParallel(t, testDemoApp, run)
	runner.Test(t, cleanup)
}

func DemoAppChecker(kernelVersion string) ec.MultiEventChecker {
	jobpostingChecker := ec.NewProcessChecker().
		WithBinary(sm.Full("/usr/local/bin/node")).
		WithArguments(sm.Full("server.js")).
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":               *sm.Full("jobposting"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			})).
		WithUid(0)

	recruiterChecker := ec.NewProcessChecker().
		WithBinary(sm.Full("/usr/local/bin/node")).
		WithArguments(sm.Full("server.js")).
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":               *sm.Full("recruiter"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			})).
		WithUid(0)

	loaderChecker := ec.NewProcessChecker().
		WithBinary(sm.Full("/usr/local/bin/node")).
		WithArguments(sm.Full("server.js")).
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":               *sm.Full("loader"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			})).
		WithUid(0)

	kafkaChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app.kubernetes.io/instance":         *sm.Full("jobs-app"),
				"app.kubernetes.io/managed-by":       *sm.Full("strimzi-cluster-operator"),
				"app.kubernetes.io/name":             *sm.Full("kafka"),
				"app.kubernetes.io/part-of":          *sm.Full("strimzi-jobs-app"),
				"controller-revision-hash":           *sm.Regex("jobs-app-kafka-[a-f0-9]+"),
				"statefulset.kubernetes.io/pod-name": *sm.Prefix("jobs-app-kafka"),
				"strimzi.io/cluster":                 *sm.Full("jobs-app"),
				"strimzi.io/kind":                    *sm.Full("Kafka"),
				"strimzi.io/name":                    *sm.Full("jobs-app-kafka"),
			})).
		WithUid(1001)

	coreapiChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":               *sm.Full("coreapi"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			})).
		WithUid(0)

	crawlerChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":               *sm.Full("crawler"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			})).
		WithUid(0)

	elasticsearchChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app":                                *sm.Full("elasticsearch-master"),
				"chart":                              *sm.Full("elasticsearch"),
				"controller-revision-hash":           *sm.Regex("elasticsearch-master-[a-f0-9]+"),
				"release":                            *sm.Full("jobs-app"),
				"statefulset.kubernetes.io/pod-name": *sm.Prefix("elasticsearch-master"),
			})).
		WithUid(0)

	zookeeperChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"app.kubernetes.io/instance":         *sm.Full("jobs-app"),
				"app.kubernetes.io/managed-by":       *sm.Full("strimzi-cluster-operator"),
				"app.kubernetes.io/name":             *sm.Full("zookeeper"),
				"app.kubernetes.io/part-of":          *sm.Full("strimzi-jobs-app"),
				"controller-revision-hash":           *sm.Regex("jobs-app-zookeeper-[a-f0-9]+"),
				"statefulset.kubernetes.io/pod-name": *sm.Prefix("jobs-app-zookeeper"),
				"strimzi.io/cluster":                 *sm.Full("jobs-app"),
				"strimzi.io/kind":                    *sm.Full("Kafka"),
				"strimzi.io/name":                    *sm.Full("jobs-app-zookeeper"),
			})).
		WithUid(1001)

	strimziChecker := ec.NewProcessChecker().
		WithPod(ec.NewPodChecker().
			WithNamespace(sm.Full(namespace)).
			WithPodLabels(map[string]sm.StringMatcher{
				"name":              *sm.Full("strimzi-cluster-operator"),
				"pod-template-hash": *sm.Regex("[a-f0-9]+"),
				"strimzi.io/kind":   *sm.Full("cluster-operator"),
			})).
		WithUid(1001)

	demoAppChecker := ec.NewUnorderedEventChecker(
		// jobposting pod
		ec.NewProcessExecChecker().
			WithProcess(jobpostingChecker).
			WithParent(ec.NewProcessChecker().
				WithBinary(sm.Full("/bin/sh")).
				WithArguments(sm.Full("-c \"PORT=9080 node server.js\"")),
			),
		ec.NewProcessListenChecker().
			WithProcess(jobpostingChecker).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithIp(sm.Regex(`^(0\.0\.0\.0|::)$`)).
			WithPort(9080),

		// recruiter pod
		ec.NewProcessExecChecker().
			WithProcess(recruiterChecker).
			WithParent(ec.NewProcessChecker().
				WithBinary(sm.Full("/bin/sh")).
				WithArguments(sm.Full("-c \"PORT=9080 node server.js\""))),
		ec.NewProcessListenChecker().
			WithProcess(recruiterChecker).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithIp(sm.Regex(`^(0\.0\.0\.0|::)$`)).
			WithPort(9080),

		// loader pod
		ec.NewProcessExecChecker().
			WithProcess(loaderChecker).
			WithParent(ec.NewProcessChecker().
				WithBinary(sm.Full("/usr/local/bin/docker-entrypoint.sh")).
				WithArguments(sm.Full("/usr/local/bin/docker-entrypoint.sh node server.js"))),
		ec.NewProcessListenChecker().
			WithProcess(loaderChecker).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithIp(sm.Regex(`^(0\.0\.0\.0|::)$`)).
			WithPort(50051),
		ec.NewProcessConnectChecker().
			WithProcess(loaderChecker).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker().
			WithProcess(loaderChecker).
			WithProtocol(tetragon.SocketProtocol_UDP),

		// coreapi pod
		ec.NewProcessExecChecker().WithProcess(coreapiChecker),

		// crawler pod
		ec.NewProcessExecChecker().WithProcess(crawlerChecker),

		// elasticsearch pod
		ec.NewProcessExecChecker().WithProcess(elasticsearchChecker),

		// kafka deployment
		ec.NewProcessExecChecker().
			WithProcess(kafkaChecker),

		// zookeeper deployment
		ec.NewProcessExecChecker().WithProcess(zookeeperChecker),

		// strimzi cluster operator
		ec.NewProcessExecChecker().WithProcess(strimziChecker),
	)

	if kernels.MinKernelVersion("5.4.0") { // No DNS support for kernels <v5.4
		// loader pod
		demoAppChecker.AddChecks(
			ec.NewProcessDnsChecker().
				WithProcess(loaderChecker).
				WithDns(ec.NewDnsInfoChecker().
					WithNames(ec.NewStringListMatcher().
						WithOperator(listmatcher.Ordered).
						WithValues(
							sm.Full("jobs-app-kafka-brokers.tenant-jobs.svc."),
						))),
			ec.NewProcessDnsChecker().
				WithProcess(loaderChecker).
				WithDns(ec.NewDnsInfoChecker().
					WithNames(ec.NewStringListMatcher().
						WithOperator(listmatcher.Ordered).
						WithValues(
							sm.Full("jobs-app-kafka-brokers.tenant-jobs.svc."),
						)).
					WithResponse(true).
					WithRcode(3)),
		)
	}

	return demoAppChecker
}
