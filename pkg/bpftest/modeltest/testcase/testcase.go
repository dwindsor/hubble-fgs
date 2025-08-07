// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testcase

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/checklist"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

func (tc *TestCase) Run(ctx context.Context, tb testing.TB, server *server.Server, harness *harness.Harness) {
	if tc.Skip != "" {
		tb.Skip(tc.Skip)
	}

	require.NoError(tb, tc.modelSetup(ctx, tb, harness), "failed to set up application model")

	model, err := server.GetModel(ctx, &v1alpha.GetModelRequest{
		Host: true,
	})
	require.NoError(tb, err, "failed to get model")

	tc.modelCheck(tb, model.GetModel().GetApplicationModel())
}

func (tc *TestCase) modelCheck(tb testing.TB, model *v1alpha.ApplicationModel) {
	m, err := json.Marshal(model)
	if err != nil {
		tb.Logf("warning: failed to marshal app model: %s", err)
	}
	fmt.Println(string(m))

	assert.True(tb, checkProcesses(tb, tc.Host, model.Host.Processes), "host process checks failed")
	assert.True(tb, checkNamespaces(tb, tc.Namespaces, model.Namespaces), "namespace checks failed")
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
		if !assert.True(tb, checkContainers(tb, check.Containers, workload.Processes), "pod checks failed in workload %q", workload.Name) {
			continue
		}
		cl.Check(workload.Name)
	}

	return true
}

func checkContainers(tb testing.TB, checks model.Containers, processes []*v1alpha.ApplicationProcessGroup) bool {
	cl := checklist.New("container", checks)
	for containerName, check := range checks {
		if !assert.True(tb, checkProcesses(tb, []model.Binary{check.Cmd}, processes), "cmd check failed in container %q", containerName) {
			continue
		}
		cl.Check(containerName)
	}
	return cl.AssertComplete(tb)
}

func checkProcesses(tb testing.TB, checks []model.Binary, processes []*v1alpha.ApplicationProcessGroup) bool {
	binaryKeys := make(map[string]struct{})
	for _, check := range checks {
		binaryKeys[check.String()] = struct{}{}
	}
	cl := checklist.New("process", binaryKeys)

	for _, check := range checks {
		found := false

		// Resolve binary if possible, otherwise fall back to original value
		binary, err := exec.LookPath(check.Cmd)
		if err != nil {
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

		numChecked := 0
		for _, process := range processes {
			numChecked++
			if process.Name == binary && process.Arguments == strings.Join(args, " ") {
				found = true
			}
		}

		if !found {
			continue
		}
		cl.Check(check.String())
	}

	return cl.AssertComplete(tb)
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
	statusChan := make(chan model.CmdResult, len(tc.Host))

	// Run binaries in parallel
	for _, binary := range tc.Host {
		go binary.Run(ctx, statusChan)
	}

	// Collect results
	for range tc.Host {
		status := <-statusChan
		if status.Err != nil {
			cmd := strings.Join(append([]string{status.Cmd}, status.Args...), " ")
			return fmt.Errorf("command %q failed: %w", cmd, status.Err)
		}
	}

	return nil
}

func (tc *TestCase) createPods(tb testing.TB, harness *harness.Harness) {
	for namespace, pods := range tc.Namespaces {
		for podName, pod := range pods {
			harness.AddPod(tb, podName, namespace, pod.Containers)
		}
	}
}
