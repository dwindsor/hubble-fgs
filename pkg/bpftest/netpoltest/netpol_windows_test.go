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
)

func TestNetworkPolicyHostSupport(t *testing.T) {

	bpftest.StartMinimalTetragonModel(context.Background(), t)

	testutils.StartSimpleHTTPServer(t, ":8080")
	testutils.StartSimpleHTTPServer(t, ":8081")

	pShellArgDenied := []string{"Invoke-WebRequest", "-UseBasicParsing", "127.0.0.1:8080"}
	pShellArgAllowed := []string{"Invoke-WebRequest", "-UseBasicParsing", "127.0.0.1:8081"}

	pShellCmd := exec.Command("powershell.exe", pShellArgDenied...)
	err := pShellCmd.Run()
	require.NoError(t, err, "no NetworkPolicy, packet should pass")

	pShellCmd = exec.Command("powershell.exe", pShellArgAllowed...)
	err = pShellCmd.Run()
	require.NoError(t, err, "no NetworkPolicy, packet should pass")

	const policyDenyYAML = `apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "host-support-test"
spec:
  processSelector:
    operator: "In"
    values:
      - "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
        ports: [8081]`

	const policyAllowYAML = `apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "host-support-test"
spec:
  processSelector:
    operator: "In"
    values:
      - "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  defaultAction: "allow"
  rules:
  - description: "connectDenyRule"
    hook: "connect"
    action: "deny"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
        ports: [8080]`

	denyPolicy, err := netpol.FromYAML(policyDenyYAML)
	require.NoError(t, err)
	err = netpol.Add(denyPolicy)
	require.NoError(t, err)

	pShellCmd = exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pShellArgAllowed...)

	err = pShellCmd.Run()
	require.NoError(t, err, "allow rule, packet should pass")

	pShellCmd = exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pShellArgDenied...)
	err = pShellCmd.Run()
	require.Error(t, err, "default deny rule, packet should drop")

	err = netpol.Delete(denyPolicy)
	require.NoError(t, err)

	allowPolicy, err := netpol.FromYAML(policyAllowYAML)
	require.NoError(t, err)
	err = netpol.Add(allowPolicy)
	require.NoError(t, err)

	pShellCmd = exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pShellArgAllowed...)

	err = pShellCmd.Run()
	require.NoError(t, err, "allow rule, packet should pass")

	pShellCmd = exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pShellArgDenied...)
	err = pShellCmd.Run()
	require.Error(t, err, "default deny rule, packet should drop")

}
