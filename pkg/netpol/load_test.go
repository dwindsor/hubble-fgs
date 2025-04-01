package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestFromYAML(t *testing.T) {
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
  - hook: "connect"
    action: "allow"
    destination:
    - matchLabels:
        "app.kubernetes.io/name": "tetragon-aggregator"
        C: "c"
        D: "c"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
    - fqdn:
      - "ebpf.io"
      - "tetragon.io"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
`
	tnp, err := fromYAML(policy)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(tnp.Spec.PodSelector.MatchLabels))
	assert.Equal(t, "In", tnp.Spec.ProcessSelector.Operator)
	assert.Equal(t, 2, len(tnp.Spec.ProcessSelector.Values))
	assert.Equal(t, "deny", tnp.Spec.DefaultAction)
	assert.Equal(t, 1, len(tnp.Spec.Rules))
	assert.Equal(t, "connect", tnp.Spec.Rules[0].Hook)
	assert.Equal(t, "allow", tnp.Spec.Rules[0].Action)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination))
	assert.Equal(t, 3, len(tnp.Spec.Rules[0].Destination[0].MatchLabels))
	key, ok := tnp.Spec.Rules[0].Destination[0].MatchLabels["app.kubernetes.io/name"]
	assert.True(t, ok)
	assert.Equal(t, "tetragon-aggregator", key)
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[0].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[0].Ports.Ports))
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].FQDN))
	assert.Equal(t, "ebpf.io", tnp.Spec.Rules[0].Destination[1].FQDN[0])
	assert.Equal(t, "tetragon.io", tnp.Spec.Rules[0].Destination[1].FQDN[1])
	assert.Equal(t, "TCP", tnp.Spec.Rules[0].Destination[1].Ports.Protocol)
	assert.Equal(t, 2, len(tnp.Spec.Rules[0].Destination[1].Ports.Ports))
}
