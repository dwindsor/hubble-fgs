//go:build sudo_tests

package netpoltest

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	"github.com/isovalent/hubble-fgs/pkg/testutils"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func TestNetworkPolicyHostSupport(t *testing.T) {
	if !utils.SupportProcessTree() {
		t.Skip()
	}

	bpftest.StartMinimalTetragonModel(context.Background(), t)

	testutils.StartSimpleHTTPServer(t, ":8080")
	testutils.StartSimpleHTTPServer(t, ":8081")

	curlArgDenied := []string{"--max-time", "0.1", "--ipv4", "http://localhost:8080"}
	curlArgAllowed := []string{"--max-time", "0.1", "--ipv4", "http://localhost:8081"}

	curlCmd := exec.Command("curl", curlArgDenied...)
	err := curlCmd.Run()
	require.NoError(t, err, "no NetworkPolicy, packet should pass")

	curlCmd = exec.Command("curl", curlArgAllowed...)
	err = curlCmd.Run()
	require.NoError(t, err, "no NetworkPolicy, packet should pass")

	const policyYAML = `apiVersion: cilium.io/v1alpha1
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

	policy, err := netpol.FromYAML(policyYAML)
	require.NoError(t, err)
	err = netpol.Add(policy)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := netpol.Delete(policy)
		require.NoError(t, err)
	})

	curlCmd = exec.Command("curl", curlArgAllowed...)
	err = curlCmd.Run()
	require.NoError(t, err, "allow rule, packet should pass")

	curlCmd = exec.Command("curl", curlArgDenied...)
	err = curlCmd.Run()
	require.Error(t, err, "default deny rule, packet should drop")
}
