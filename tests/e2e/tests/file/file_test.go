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
	"os"

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
		pr := os.Getenv("HOST_PROC")
		if pr == "" {
			pr = "/proc"
		}
		ctx, err = helpers.LoadCRDString(namespace, strings.Replace(ubuntulYaml, "HOST_PROC", pr, -1), true)(ctx, cfg)
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

			// read the /etc/shadow inside the Pod
			_, err = helpers.ExecInPodCombinedOutput(ctx,
				client,
				namespace,
				pod.Name,
				"ubuntu",
				strings.Fields("cat /etc/shadow"))
			if !assert.NoError(t, err, "failed to run cat") {
				klog.Errorf("cat failed with error: %w", err)
				return ctx
			}

			// we will run all of these commands inside the pod
			for _, cmd := range []string{
				"mkdir /etc/test_dir",
				"touch /etc/test_dir/a",
				"dd if=/dev/zero of=/etc/test_dir/a bs=64 count=1",
				"mv /etc/test_dir/a /etc/test_dir/b",
				"cat /etc/test_dir/b",
				"mv /etc/test_dir/b /etc/test_dir/c",
				"dd if=/dev/zero of=/etc/test_dir/c bs=64 count=1",
				"mv /etc/test_dir/c /etc/test_dir/d",
				"cat /etc/test_dir/d",
				"truncate -s 10 /etc/test_dir/d",
				"ls /etc/test_dir/",
				"fallocate -l 10 /etc/test_dir/e",
				"chmod 0666 /etc/test_dir/e",
				"chown root:sys /etc/test_dir/e",
				"rm /etc/test_dir/e",
				"rm /etc/test_dir/d",
				"rmdir /etc/test_dir",
			} {
				_, err = helpers.ExecInPodCombinedOutput(ctx,
					client,
					namespace,
					pod.Name,
					"ubuntu",
					strings.Fields(cmd))
				if !assert.NoError(t, err, "failed to run [%s]", cmd) {
					klog.Errorf("[%s] failed with error: %w", cmd, err)
					return ctx
				}
			}

			return ctx
		}).
		Feature()

	runner.TestInParallel(t, checkFile, testFile)
}

func createChecker(file string) *ec.FileDetailsChecker {
	return ec.NewFileDetailsChecker().WithFilename(sm.Full(file)).WithLocation(ec.NewFileLocationChecker().WithType(tetragon.FileScope_CONTAINER_FILE_LOCAL))
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

	catPodCheckerEtc := ec.NewProcessChecker().
		WithBinary(sm.Contains("cat")).
		WithArguments(sm.Contains("/etc/shadow")).
		WithPod(podChecker)

	shellChecker := ec.NewProcessChecker().
		WithBinary(sm.Contains("nsenter"))

	fileChecker := ec.NewUnorderedEventChecker(
		// 1st test
		ec.NewProcessExecChecker("catTmpExec").
			WithProcess(catCheckerTmp).
			WithParent(shellChecker),
		ec.NewProcessFileChecker("catTmpRead").
			WithProcess(catCheckerTmp).
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(ec.NewFileDetailsChecker().WithFilename(sm.Full("/tmp/testfile")).WithLocation(ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE))),
				),
			).
			WithHook(sm.Full("security_file_permission")),
		// 2nd test
		ec.NewProcessExecChecker("catEtcExec").
			WithProcess(catCheckerEtc).
			WithParent(shellChecker),
		ec.NewProcessFileChecker("catEtcRead").
			WithProcess(catCheckerEtc).
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(ec.NewFileDetailsChecker().WithFilename(sm.Full("/etc/passwd")).WithLocation(ec.NewFileLocationChecker().WithType(tetragon.FileScope_HOST_FILE))),
				),
			).
			WithHook(sm.Full("security_file_permission")),
		// 3rd test
		ec.NewProcessExecChecker("catPodEtcExec").
			WithProcess(catPodCheckerEtc),
		ec.NewProcessFileChecker("catPodEtcRead").
			WithProcess(catPodCheckerEtc).
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(
				ec.NewFileArgumentChecker().WithGenericArg(
					ec.NewGenericFileArgChecker().WithFile(ec.NewFileDetailsChecker().WithFilename(sm.Full("/etc/shadow")).WithLocation(ec.NewFileLocationChecker().WithType(tetragon.FileScope_CONTAINER_FILE_LOCAL))),
				),
			).
			WithHook(sm.Full("security_file_permission")),
		// 4th test
		ec.NewProcessFileChecker("mkdir").
			WithAction(tetragon.FileAction_FILE_MKDIR).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/")))).
			WithHook(sm.Full("vfs_mkdir")),
		ec.NewProcessFileChecker("touch").
			WithAction(tetragon.FileAction_FILE_CREATE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/a")))).
			WithHook(sm.Full("vfs_open")),
		ec.NewProcessFileChecker("dd1").
			WithAction(tetragon.FileAction_FILE_WRITE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/a")))).
			WithHook(sm.Full("security_file_permission")),
		ec.NewProcessFileChecker("mv1").
			WithAction(tetragon.FileAction_FILE_RENAME).
			WithArgs(ec.NewFileArgumentChecker().WithRenameArg(ec.NewRenameFileArgChecker().WithSrc(createChecker("/etc/test_dir/a")).WithDst(createChecker("/etc/test_dir/b")))).
			WithHook(sm.Full("vfs_rename")),
		ec.NewProcessFileChecker("cat1").
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/b")))).
			WithHook(sm.Full("security_file_permission")),
		ec.NewProcessFileChecker("mv2").
			WithAction(tetragon.FileAction_FILE_RENAME).
			WithArgs(ec.NewFileArgumentChecker().WithRenameArg(ec.NewRenameFileArgChecker().WithSrc(createChecker("/etc/test_dir/b")).WithDst(createChecker("/etc/test_dir/c")))).
			WithHook(sm.Full("vfs_rename")),
		ec.NewProcessFileChecker("dd2").
			WithAction(tetragon.FileAction_FILE_WRITE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/c")))).
			WithHook(sm.Full("security_file_permission")),
		ec.NewProcessFileChecker("mv3").
			WithAction(tetragon.FileAction_FILE_RENAME).
			WithArgs(ec.NewFileArgumentChecker().WithRenameArg(ec.NewRenameFileArgChecker().WithSrc(createChecker("/etc/test_dir/c")).WithDst(createChecker("/etc/test_dir/d")))).
			WithHook(sm.Full("vfs_rename")),
		ec.NewProcessFileChecker("cat2").
			WithAction(tetragon.FileAction_FILE_READ).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/d")))).
			WithHook(sm.Full("security_file_permission")),
		ec.NewProcessFileChecker("truncate").
			WithAction(tetragon.FileAction_FILE_WRITE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/d")))).
			WithHook(sm.Full("do_truncate")),
		ec.NewProcessFileChecker("ls").
			WithAction(tetragon.FileAction_FILE_READDIR).
			WithArgs(ec.NewFileArgumentChecker().WithReaddirArg(ec.NewReadDirArgChecker().WithFile(createChecker("/etc/test_dir/")))).
			WithHook(sm.Full("iterate_dir")),
		ec.NewProcessFileChecker("fallocateCreate").
			WithAction(tetragon.FileAction_FILE_CREATE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/e")))).
			WithHook(sm.Full("vfs_open")),
		ec.NewProcessFileChecker("fallocateWrite").
			WithAction(tetragon.FileAction_FILE_WRITE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/e")))).
			WithHook(sm.Full("vfs_fallocate")),
		ec.NewProcessFileChecker("chmod").
			WithAction(tetragon.FileAction_FILE_CHATTR).
			WithArgs(ec.NewFileArgumentChecker().WithAttrArg(ec.NewAttrArgChecker().WithFile(createChecker("/etc/test_dir/e")))).
			WithHook(sm.Full("chmod_common")),
		ec.NewProcessFileChecker("chown").
			WithAction(tetragon.FileAction_FILE_CHATTR).
			WithArgs(ec.NewFileArgumentChecker().WithAttrArg(ec.NewAttrArgChecker().WithFile(createChecker("/etc/test_dir/e")))).
			WithHook(sm.Full("chown_common")),
		ec.NewProcessFileChecker("rm1").
			WithAction(tetragon.FileAction_FILE_DELETE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/e")))).
			WithHook(sm.Full("vfs_unlink")),
		ec.NewProcessFileChecker("rm2").
			WithAction(tetragon.FileAction_FILE_DELETE).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/d")))).
			WithHook(sm.Full("vfs_unlink")),
		ec.NewProcessFileChecker("rmdir").
			WithAction(tetragon.FileAction_FILE_RMDIR).
			WithArgs(ec.NewFileArgumentChecker().WithGenericArg(ec.NewGenericFileArgChecker().WithFile(createChecker("/etc/test_dir/")))).
			WithHook(sm.Full("security_inode_rmdir")),
	)

	return fileChecker
}
