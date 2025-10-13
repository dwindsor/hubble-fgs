package policies

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testAlertRule = `apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: shell-execution
spec:
  expression: |
    process_exec.process.binary.contains("bash") || process_exec.process.binary.contains("ash") ||
    process_exec.process.binary.contains("csh") || process_exec.process.binary.contains("ksh") ||
    process_exec.process.binary.contains("dash") || process_exec.process.binary.contains("zsh")
  message: Detected shell execution.
  tags: [shell]`

var testNetworkPolicy = `apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "host-support-test"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - FQDN:
      - "localhost"
      ports:
        protocol: "TCP"
        ports: [8081]`

var testTracingPolicy = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "monitor"
spec:
  options:
  - name: "policy-mode"
    value: "monitor"
  kprobes:`

var testSandboxPolicy = `apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: "syscalls"
spec:
  syscalls:
    - list:
      - name: "sys_dup"
      - name: "sys_dup2"`

type testPolicyLoad struct {
	numTracing int
	numSandbox int
	numNetwork int
	numAlert   int
}

func (t *testPolicyLoad) OnTracingPolicy(_ context.Context, _ string, _ []byte) error {
	t.numTracing++
	return nil
}

func (t *testPolicyLoad) OnSandboxPolicy(_ context.Context, _ string, _ []byte) error {
	t.numSandbox++
	return nil
}

func (t *testPolicyLoad) OnNetworkPolicy(_ context.Context, _ string, _ []byte) error {
	t.numNetwork++
	return nil
}

func (t *testPolicyLoad) OnAlertRule(_ context.Context, _ string, _ []byte) error {
	t.numAlert++
	return nil
}

// The test checks that LoadFromDir correctly supports
// loading for all policies kinds.
func TestLoadFromDir(t *testing.T) {
	policyDir, err := os.MkdirTemp("", "test_policies")
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(policyDir)
	})

	// Generate tetragon policies
	err = os.WriteFile(filepath.Join(policyDir, "alert_rule.yaml"), []byte(testAlertRule), 0644)
	assert.NoError(t, err)

	os.WriteFile(filepath.Join(policyDir, "networkpolicy.yaml"), []byte(testNetworkPolicy), 0644)
	assert.NoError(t, err)

	os.WriteFile(filepath.Join(policyDir, "tracingpolicy.yaml"), []byte(testTracingPolicy), 0644)
	assert.NoError(t, err)

	os.WriteFile(filepath.Join(policyDir, "sandboxpolicy.yaml"), []byte(testSandboxPolicy), 0644)
	assert.NoError(t, err)

	loader := testPolicyLoad{}
	err = LoadFromDir(context.Background(), policyDir, &loader)
	assert.NoError(t, err)

	assert.Equal(t, 1, loader.numAlert)
	assert.Equal(t, 1, loader.numNetwork)
	assert.Equal(t, 1, loader.numTracing)
	assert.Equal(t, 1, loader.numSandbox)
}
