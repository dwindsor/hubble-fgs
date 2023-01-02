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

package file_test

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
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

const (
	namespace = "file"
)

//go:embed ubuntu-shared-proc.yaml
var ubuntulYaml string

//go:embed file-tracingpolicy.yaml
var tracingPolicyYaml string

func TestMain(m *testing.M) {
	runner = runners.NewRunner().WithInstallTetragon(install.WithHelmOptions(map[string]string{
		"enterprise.exportAllowList": "",
	})).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, cfg)
		ctx, err = helpers.CreateNamespace(namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create file namespace: %w", err)
		}
		ctx, err = helpers.LoadCRDString(namespace, ubuntulYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy ubuntu pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.LoadCRDString(namespace, tracingPolicyYaml, true)(ctx, cfg)
		return ctx, nil
	})

	runner.Run(m)
}

func getUbuntuPod(ctx context.Context, client klient.Client) (*corev1.Pod, error) {
	r := client.Resources(namespace)

	podList := &corev1.PodList{}
	r.List(ctx, podList)

	if len(podList.Items) != 1 {
		return nil, fmt.Errorf("expected exactly 1 ubuntu pod")
	}

	return &podList.Items[0], nil
}

func TestFile(t *testing.T) {
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)

	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("5.4.0") {
		t.Skipf("File monitoring tests need kernel >= 5.4, got %s", kversion)
	}

	fileChecker := checker.NewRPCChecker(FileChecker(), "fileChecker").WithEventLimit(1000).WithTimeLimit(3 * time.Minute)
	checkFile := features.New("Check File Events").
		Assess("Run Event Checks", fileChecker.CheckInNamespace(30*time.Second, namespace)).
		Feature()

	testFile := features.New("Test File").
		Assess("Wait For Checker", fileChecker.Wait(30*time.Second)).
		Assess("Run Cat Workload", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if !assert.NoError(t, err, "unable to get kube client") {
				return ctx
			}
			pod, err := getUbuntuPod(ctx, client)
			if !assert.NoError(t, err, "unable to get ubuntu pod") {
				return ctx
			}

			// create a file
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("nsenter --mount=/procRoot/1/ns/mnt -- dd if=/dev/zero of=/tmp/testfile bs=128 count=1"))
			if !assert.NoError(t, err, "failed to run dd") {
				klog.Errorf("dd failed with error: %w", err)
				return ctx
			}

			// read the file
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("nsenter --mount=/procRoot/1/ns/mnt -- cat /tmp/testfile"))
			if !assert.NoError(t, err, "failed to run cat") {
				klog.Errorf("cat failed with error: %w", err)
				return ctx
			}

			// delete the file
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("nsenter --mount=/procRoot/1/ns/mnt -- rm -f /tmp/testfile"))
			if !assert.NoError(t, err, "failed to run rm") {
				klog.Errorf("rm failed with error: %w", err)
				return ctx
			}

			// read the /etc/passwd (in GKE this is over an overlayfs with xino=off)
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("nsenter --mount=/procRoot/1/ns/mnt -- cat /etc/passwd"))
			if !assert.NoError(t, err, "failed to run cat") {
				klog.Errorf("cat failed with error: %w", err)
				return ctx
			}

			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkFile, testFile)
}

func FileChecker() ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("ubuntu")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/library/ubuntu:20.04")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full("file")).
		WithName(sm.Prefix("ubuntu")).
		WithLabels(map[string]sm.StringMatcher{
			"k8s:app":                                 *sm.Full("ubuntu"),
			"k8s:io.cilium.k8s.policy.cluster":        *sm.Contains(helpers.GetClusterName()),
			"k8s:io.cilium.k8s.policy.serviceaccount": *sm.Full("default"),
			"k8s:io.kubernetes.pod.namespace":         *sm.Full("file"),
		}).
		WithContainer(containerChecker)

	catCheckerTmp := ec.NewProcessChecker().
		WithBinary(sm.Contains("cat")).
		WithArguments(sm.Contains("/tmp/testfile")).
		WithPod(podChecker)

	catCheckerEtc := ec.NewProcessChecker().
		WithBinary(sm.Contains("cat")).
		WithArguments(sm.Contains("/etc/passwd")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("nsenter"))

	fileChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(catCheckerTmp).
			WithParent(shellChecker),
		ec.NewProcessFileChecker().
			WithProcess(catCheckerTmp).
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(ec.NewFileDetailsChecker().WithFilename(sm.Full("/tmp/testfile"))),
				),
			).
			WithHook(sm.Full("rw_verify_area")),
		ec.NewProcessExecChecker().
			WithProcess(catCheckerEtc).
			WithParent(shellChecker),
		ec.NewProcessFileChecker().
			WithProcess(catCheckerEtc).
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(ec.NewFileDetailsChecker().WithFilename(sm.Full("/etc/passwd"))),
				),
			).
			WithHook(sm.Full("rw_verify_area")),
	)

	return fileChecker
}
