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
  rules:
  - hook: "connect"
    action: "deny"
    destination:
    - labels:
        matchLabels: ["C=c", "D=d"]
      action: "allow"
    - fqdn:
        fqdn: ["ebpf.io", "tetragon.io"]
      action: "allow"
`
	_, err := fromYAML(policy)
	assert.NoError(t, err)
}
