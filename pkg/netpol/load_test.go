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
          C: "c"
      ports:
        protocol: "TCP"
        ports: [80, 8080]
    - fqdn:
        fqdn: ["ebpf.io", "tetragon.io"]
      ports:
        protocol: "TCP"
        ports: [80, 8080]
`
	_, err := fromYAML(policy)
	assert.NoError(t, err)
}
