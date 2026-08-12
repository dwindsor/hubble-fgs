// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package testcase

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/checklist"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/deps"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/utils"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
)

// TestCase defines a single model test case.
//
// Specifically, it determines the shape of the process tree created by the
// Harness and any subsequent checks on the resulting application model.
type TestCase struct {
	// If non-empty, skip the test with a message
	Skip string
	// Binaries that run directly on the host.
	Host model.Binaries
	// Namespaces that contain pods.
	Namespaces model.Namespaces

	// A process registry that the various run commands can use to coordinate with each other.
	ProcessRegistry *deps.ProcessRegistry

	// A sequence of additional steps to perform. The step is an arbitrary
	// function, but the expectation is that the step modifies either the
	// server, harness, or Host/Namespaces in the TestCase. After each step, the
	// TestCase will call server.GetModel and tc.modelCheck to compare the
	// generated application model against the contents of Host/Namespaces.
	Steps []func(ctx context.Context, tb testing.TB, tc *TestCase, server *server.Server, harness *harness.Harness)

	// A set of host processes and namespaces that must *not* be present in the application model.
	NotInModel model.NotPresent
}

func (tc *TestCase) Run(ctx context.Context, tb testing.TB, server *server.Server, harness *harness.Harness) {
	if tc.Skip != "" {
		tb.Skip(tc.Skip)
	}

	tc.ProcessRegistry = deps.NewProcessRegistry()
	defer tc.ProcessRegistry.Cleanup()

	require.NoError(tb, tc.modelSetup(ctx, tb, harness), "failed to set up application model")

	tc.modelCheck(ctx, tb, server)

	for _, step := range tc.Steps {
		step(ctx, tb, tc, server, harness)

		tc.modelCheck(ctx, tb, server)
	}
}

func (tc *TestCase) modelCheck(ctx context.Context, tb testing.TB, server *server.Server) {

	model, err := server.GetModel(ctx, &v1alpha.GetModelRequest{
		Host: true,
	})
	require.NoError(tb, err, "failed to get model")

	amodel := model.GetModel().GetApplicationModel()

	utils.RegisterModelDump(tb, amodel)

	assert.True(tb, checkProcesses(tb, tc.Host, amodel.Host.Processes, false), "host process checks failed")
	assert.True(tb, checkNamespaces(tb, tc.Namespaces, amodel.Namespaces), "namespace checks failed")

	assert.True(tb, checkNotPresentProcesses(tb, tc.NotInModel.Host, amodel.Host.Processes, false), "host not present process checks failed")
	assert.True(tb, checkNotPresentNamespaces(tb, tc.NotInModel.Namespaces, amodel.Namespaces), "not present namespace checks failed")
}

func checkNamespaces(tb testing.TB, checks model.Namespaces, namespaces []*v1alpha.ApplicationNamespace) bool {
	// If we were expecting namespace information in the application model but there is none, fail the assertion and return early.
	if len(checks) != 0 && !assert.Greater(tb, len(namespaces), 0, "no namespace data in application model") {
		return false
	}

	cl := checklist.New("namespace", checks)
	for _, namespace := range namespaces {
		check, ok := checks[namespace.Name]
		if !ok {
			continue
		}
		if !assert.True(tb, checkWorkloads(tb, check, namespace.Workloads), "workload checks failed in namespace %q", namespace.Name) {
			continue
		}
		cl.Check(namespace.Name)
	}

	return cl.AssertComplete(tb)
}

func checkWorkloads(tb testing.TB, checks model.Pods, workloads []*v1alpha.ApplicationWorkload) bool {
	cl := checklist.New("workload", checks)
	for _, workload := range workloads {
		check, ok := checks[workload.Name]
		if !ok {
			continue
		}
		if !assert.True(tb, checkContainers(tb, check.Containers, workload.Containers), "pod checks failed in workload %q", workload.Name) {
			continue
		}
		cl.Check(workload.Name)
	}

	return cl.AssertComplete(tb)
}

func checkContainers(tb testing.TB, checks model.Containers, containers []*v1alpha.ApplicationContainer) bool {
	cl := checklist.New("container", checks)
	for _, container := range containers {
		check, ok := checks[container.Name]
		if !ok {
			continue
		}
		if !assert.True(tb, checkProcesses(tb, []model.Binary{check.Cmd}, container.Processes, true), "cmd check failed in container %q", container.Name) {
			continue
		}
		cl.Check(container.Name)
	}
	return cl.AssertComplete(tb)
}

func checkProcesses(tb testing.TB, checks []model.Binary, processes []*v1alpha.ApplicationProcessGroup, isContainer bool) bool {
	binaryKeys := make(map[string]struct{})
	for _, check := range checks {
		binaryKeys[check.String()] = struct{}{}
	}
	cl := checklist.New("process", binaryKeys)

	for _, check := range checks {
		found := false

		var binary string
		if !isContainer {
			binary = utils.FixupBinaryPathname(check.Cmd)
		} else {
			binary = check.Cmd
		}

		// Fixup args containing spaces to match app model encoding
		var args []string
		for _, arg := range check.Args {
			if strings.ContainsRune(arg, ' ') {
				args = append(args, fmt.Sprintf("%q", arg))
				continue
			}
			args = append(args, arg)
		}

		expectedArgs := strings.Join(args, " ")

		numChecked := 0
		for _, process := range processes {
			numChecked++
			if process.Name == binary {
				if process.Arguments != expectedArgs {
					for i := 0; i < len(expectedArgs) && i < len(process.Arguments); i++ {
						if expectedArgs[i] != process.Arguments[i] {
							break
						}
					}
				}
			}
			if process.Name == binary && process.Arguments == expectedArgs {
				found = true

				if !check.SkipExecExitCounts {
					// By default every program runs once and exits once
					var execCount uint64 = 1
					var exitCount uint64 = 1

					if check.LongLived {
						exitCount = 0
					}

					assert.Equal(tb, execCount, process.ExecutionCount, "Unexpected exec count for process %q: expected %d, got %d", check.String(), execCount, process.ExecutionCount)
					assert.Equal(tb, exitCount, process.ExitCount, "Unexpected exit count for process %q: expected %d, got %d", check.String(), exitCount, process.ExitCount)
				}

				assert.True(tb, check.CheckConnections(tb, process.Connections))
			}
		}

		if !found {
			continue
		}
		cl.Check(check.String())
	}

	return cl.AssertComplete(tb)
}

func checkNotPresentNamespaces(tb testing.TB, checks model.Namespaces, namespaces []*v1alpha.ApplicationNamespace) bool {

	ok := true

	for _, namespace := range namespaces {
		check, exists := checks[namespace.Name]
		if !exists {
			continue
		}

		if len(check) == 0 {
			// Don't care about contents, if the namespace is present, it's a failure.
			assert.Fail(tb, fmt.Sprintf("unexpected namespace present: %s", namespace.Name))
			ok = false
		} else {
			if !checkNotPresentWorkloads(tb, check, namespace.Workloads) {
				ok = false
			}
		}
	}

	return ok
}

func checkNotPresentWorkloads(tb testing.TB, checks model.Pods, workloads []*v1alpha.ApplicationWorkload) bool {
	ok := true

	for _, workload := range workloads {
		check, exists := checks[workload.Name]
		if !exists {
			continue
		}

		if len(check.Containers) == 0 {
			// Don't care about contents, if the workload is present, it's a failure.
			assert.Fail(tb, fmt.Sprintf("unexpected workload present: %s", workload.Name))
			ok = false
		} else {
			if !checkNotPresentContainers(tb, check.Containers, workload.Containers) {
				ok = false
			}
		}
	}

	return ok
}

func checkNotPresentContainers(tb testing.TB, checks model.Containers, containers []*v1alpha.ApplicationContainer) bool {
	ok := true

	for _, container := range containers {
		check, exists := checks[container.Name]
		if !exists {
			continue
		}
		if check.Cmd.Cmd == "" {
			// Don't care about contents, if the container is present, it's a failure.
			assert.Fail(tb, fmt.Sprintf("unexpected container present: %s", container.Name))
			ok = false
		} else {
			if !checkNotPresentProcesses(tb, []model.Binary{check.Cmd}, container.Processes, true) {
				ok = false
			}
		}
	}

	return ok
}

func checkNotPresentProcesses(tb testing.TB, checks []model.Binary, processes []*v1alpha.ApplicationProcessGroup, isContainer bool) bool {
	ok := true

	for _, check := range checks {

		var binary string
		if !isContainer {
			binary = utils.FixupBinaryPathname(check.Cmd)
		} else {
			binary = check.Cmd
		}

		// Fixup args containing spaces to match app model encoding
		var args []string
		for _, arg := range check.Args {
			if strings.ContainsRune(arg, ' ') {
				args = append(args, fmt.Sprintf("%q", arg))
				continue
			}
			args = append(args, arg)
		}

		expectedArgs := strings.Join(args, " ")

		for _, process := range processes {
			if process.Name == binary && process.Arguments == expectedArgs {
				assert.Fail(tb, fmt.Sprintf("unexpected process present: %s %s", binary, expectedArgs))
				ok = false
			}
		}
	}

	return ok
}

func (tc *TestCase) modelSetup(ctx context.Context, tb testing.TB, harness *harness.Harness) error {
	// Run binaries on the host
	if err := tc.runHostBinaries(ctx); err != nil {
		return err
	}

	// Create pods
	tc.createPods(tb, harness)

	return nil
}

func (tc *TestCase) runHostBinaries(ctx context.Context) error {
	if len(tc.Host) == 0 {
		return nil
	}

	statusChan := make(chan model.CmdResult, len(tc.Host))

	// Run binaries in parallel
	for _, binary := range tc.Host {
		go binary.Run(ctx, tc.ProcessRegistry, statusChan)
	}

	// Collect results
	for range tc.Host {
		err := tc.collectBinaryStatus(statusChan)
		if err != nil {
			return err
		}
	}

	return nil
}

func (tc *TestCase) RunSingleBinary(ctx context.Context, binary model.Binary) error {
	statusChan := make(chan model.CmdResult, 1)

	go binary.Run(ctx, tc.ProcessRegistry, statusChan)

	return tc.collectBinaryStatus(statusChan)
}

func (tc *TestCase) collectBinaryStatus(statusChan <-chan model.CmdResult) error {
	status := <-statusChan
	if status.Err != nil {
		cmd := strings.Join(append([]string{status.Cmd}, status.Args...), " ")
		return fmt.Errorf("command %q failed: %w", cmd, status.Err)
	}
	return nil
}

func (tc *TestCase) createPods(tb testing.TB, harness *harness.Harness) {
	for namespace, pods := range tc.Namespaces {
		for podName, pod := range pods {
			harness.AddPod(tb, podName, namespace, pod.RestartPolicy, pod.Containers)
		}
	}
}
