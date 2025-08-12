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

//go:build !windows

package fileDispatcher

import (
	"context"
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/tests/e2e/tests/common/file"

	"k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	lm "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
)

const (
	Namespace = "file-dispatcher"
)

//go:embed ubuntu-simple-pod.yaml
var UbuntulDefaultYaml string

//go:embed policy-prefix.yaml
var PolicyPrefixYaml string

//go:embed policy-suffix.yaml
var PolicySuffixYaml string

func Test(t *testing.T, runner *runners.Runner) {
	// FIM dispatcher works only on kernels >= 6.1
	kversion := helpers.GetMinKernelVersion(t, runner.Environment)
	if kernels.KernelStringToNumeric(kversion) < kernels.KernelStringToNumeric("6.1.0") {
		t.Skipf("FIM dispatcher tests need kernel >= 6.1, got %s", kversion)
	}

	fileChecker := checker.NewRPCChecker(Checker(), "fileChecker").WithEventLimit(1000).WithTimeLimit(3 * time.Minute)
	checkFile := features.New("Check File Events").
		Assess("Run Event Checks", fileChecker.CheckInNamespace(30*time.Second, []string{Namespace, "default"}...)).
		Feature()

	testFile := features.New("Test File").
		Assess("Wait For Checker", fileChecker.Wait(30*time.Second)).
		Assess("Run File Workload", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if !assert.NoError(t, err, "unable to get kube client") {
				return ctx
			}

			pod, err := file.GetUbuntuPod(ctx, client, Namespace)
			if !assert.NoError(t, err, "unable to get ubuntu pod") {
				return ctx
			}

			// create a file that match both if the tracing policies
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				Namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("touch /pizza.foo.pizza"))
			if !assert.NoError(t, err, "failed to run touch") {
				klog.Errorf("touch failed with error: %s", err)
				return ctx
			}

			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkFile, testFile)
}

func Checker() ec.MultiEventChecker {
	containerChecker := ec.NewContainerChecker().
		WithName(sm.Full("ubuntu")).
		WithImage(ec.NewImageChecker().WithName(sm.Full("docker.io/library/ubuntu:22.04")))

	podChecker := ec.NewPodChecker().
		WithNamespace(sm.Full(Namespace)).
		WithName(sm.Full("ubuntu")).
		WithWorkload(sm.Full("ubuntu")).
		WithWorkloadKind(sm.Full("Pod")).
		WithContainer(containerChecker).
		WithPodLabels(map[string]sm.StringMatcher{
			"app":    *sm.Full("ubuntu"),
			"prefix": *sm.Full("enabled"),
			"suffix": *sm.Full("enabled"),
		})

	touchChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("touch")).
		WithArguments(sm.Full("/pizza.foo.pizza")).
		WithPod(podChecker)

	obsChecks := []ec.EventChecker{
		ec.NewProcessFileChecker("touchLabelPrefix").
			WithProcess(touchChecker).
			WithAction(tetragon.FileAction_FILE_OPEN).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(
						ec.NewFileDetailsChecker().
							WithStr(sm.Full("/pizza.foo.pizza")).
							WithOpenFlags(
								ec.NewStringListMatcher().
									WithOperator(lm.Subset).
									WithValues(sm.Full("O_CREAT")),
							),
					),
				),
			).
			WithHook(sm.Full("security_file_open")).
			WithOperation(ec.NewFileOperationListMatcher().
				WithOperator(lm.Ordered).
				WithValues(
					ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_POST),
				)).
			WithTracingPolicy(sm.Full("fim-prefix")),
		ec.NewProcessFileChecker("touchLabelSuffix").
			WithProcess(touchChecker).
			WithAction(tetragon.FileAction_FILE_OPEN).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(
						ec.NewFileDetailsChecker().
							WithStr(sm.Full("/pizza.foo.pizza")).
							WithOpenFlags(
								ec.NewStringListMatcher().
									WithOperator(lm.Subset).
									WithValues(sm.Full("O_CREAT")),
							),
					),
				),
			).
			WithHook(sm.Full("security_file_open")).
			WithOperation(ec.NewFileOperationListMatcher().
				WithOperator(lm.Ordered).
				WithValues(
					ec.NewFileOperationChecker(tetragon.FileOperation_FILE_OP_POST),
				)).
			WithTracingPolicy(sm.Full("fim-suffix")),
	}
	return ec.NewUnorderedEventChecker(obsChecks...)
}
