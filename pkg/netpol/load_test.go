package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  namespaceSelector:
    matchLabels:
      AS: "ns"
      BS: "bs"
  podSelector:
    matchLabels:
      A: "a"
      B: "b"
  processSelector:
    operator: "In"
    values:
    - "/usr/bin/curl"
    - "/usr/local/bin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
    - ipBlock:
        cidr: "127.0.0.1/24"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	require.NoError(t, err)
	assert.Equal(t, 2, len(tnp.Spec.NamespaceSelector.MatchLabels))
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connectAllowRule", tnp.Spec.Rules[0].Description)
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
	assert.Equal(t, "127.0.0.1/24", tnp.Spec.Rules[0].Destination[2].IPBlock.CIDR)
}

func TestFromYAMLFQDN(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  podSelector:
    matchLabels:
      A: "a"
      B: "b"
  processSelector:
    operator: "In"
    values:
    - "/usr/bin/curl"
    - "/usr/local/bin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Destination))

	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[0].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[0].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[0].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
}

func TestFromYAMLMatchLabels(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  podSelector:
    matchLabels:
      A: "a"
      B: "b"
  processSelector:
    operator: "In"
    values:
    - "/usr/bin/curl"
    - "/usr/local/bin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Destination))

	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
}

func TestFromYAMLNoPorts(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  podSelector:
    matchLabels:
      A: "a"
      B: "b"
  processSelector:
    operator: "In"
    values:
    - "/usr/bin/curl"
    - "/usr/local/bin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
}

func TestFromYAMLPartialSubjectPod(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  podSelector:
    matchLabels:
      A: "a"
      B: "b"
  defaultAction: "deny"
  rules:
  - description: "connectAllowRule"
    hook: "connect"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Nil(t, tnp.Spec.ProcessSelector)
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
}

func TestFromYAMLPartialSubjectProcess(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  processSelector:
    operator: "In"
    values:
    - "/usr/bin/curl"
    - "/usr/local/bin/curl"
  defaultAction: "deny"
  rules:
  - hook: "connect"
    description: "connectAllowRule"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.PodSelector)
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
}

func TestFromYAMLPartialMissingSubject(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  defaultAction: "deny"
  rules:
  - hook: "connect"
    description: "connectAllowRule"
    action: "allow"
    destination:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: tetragon-aggregator
          C: "c"
          D: "d"
      ports:
        protocol: "TCP"
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Nil(t, tnp.Spec.PodSelector)
	assert.Nil(t, tnp.Spec.ProcessSelector)

	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].PodSelector.MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
}

func TestFromYAMLNothing(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  defaultAction: "deny"
  rules:
  - hook: "connect"
    description: "connectAllowRule"
    action: "allow"
    destination:
`
	tnp, err := FromYAML(policy)
	assert.NoError(t, err)
	assert.Nil(t, tnp.Spec.NamespaceSelector)
	assert.Nil(t, tnp.Spec.PodSelector)
	assert.Nil(t, tnp.Spec.ProcessSelector)

	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 0, len(tnp.Spec.Rules[0].Destination))
}

func TestFromLogicalVRFNetworks(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  logicalNetworkSelector:
    vrf: "red"
  defaultAction: "deny"
  rules:
  - description: "smartswitchRedPolicy"
    hook: "firewall"
    action: "allow"
    source:
    - ipBlock:
        cidr: "10.1.0.1/16"
      ports:
        protocol: "TCP"
    destination:
    - ipBlock:
        cidr: "10.2.0.1/16"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	require.NoError(t, err)
	assert.Equal(t, "red", tnp.Spec.LogicalNetworkSelector.VRF)

	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, "smartswitchRedPolicy", tnp.Spec.Rules[0].Description)
	assert.Equal(t, "firewall", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)

	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, "10.2.0.1/16", tnp.Spec.Rules[0].Destination[0].IPBlock.CIDR)

	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Source))
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Source[0].Ports.Protocol)
	assert.Equal(t, "10.1.0.1/16", tnp.Spec.Rules[0].Source[0].IPBlock.CIDR)
}

func TestFromLogicalVLANNetworks(t *testing.T) {
	policy :=
		`apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "example-label-segmentation"
  annotations:
    author: "IsovalentQATeam"
spec:
  logicalNetworkSelector:
    vlan: 10
  defaultAction: "deny"
  rules:
  - description: "smartswitchRedPolicy"
    hook: "firewall"
    action: "allow"
    source:
    - ipBlock:
        cidr: "10.1.0.1/16"
      ports:
        protocol: "TCP"
    destination:
    - ipBlock:
        cidr: "10.2.0.1/16"
      ports:
        protocol: "TCP"
`
	tnp, err := FromYAML(policy)
	require.NoError(t, err)
	assert.Equal(t, uint32(10), tnp.Spec.LogicalNetworkSelector.VLAN)

	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, "smartswitchRedPolicy", tnp.Spec.Rules[0].Description)
	assert.Equal(t, "firewall", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)

	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, "10.2.0.1/16", tnp.Spec.Rules[0].Destination[0].IPBlock.CIDR)

	assert.Equal(t, 1, len(tnp.Spec.Rules[0].Source))
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Source[0].Ports.Protocol)
	assert.Equal(t, "10.1.0.1/16", tnp.Spec.Rules[0].Source[0].IPBlock.CIDR)
}
