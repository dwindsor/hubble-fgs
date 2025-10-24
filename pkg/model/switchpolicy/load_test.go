package switchpolicy

import (
	"os"
	"testing"
)

var data = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: microsegmentation-policy
  namespace: default
spec:
  rules:
  - action: allow
    description: Allow ICMP ping for network diagnostics
    destination:
      ipBlock:
      - cidr: 192.168.0.0/16
        vrf: management
      protoPorts:
      - protocol: icmp
    source:
      ipBlock:
      - cidr: 192.168.1.10/32
        vrf: management
`

func TestFromFile(t *testing.T) {
	f, err := os.CreateTemp("", "test-policy-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(data); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	_, err = FromFile(f.Name())
	if err != nil {
		t.Fatalf("failed: %s", err)
	}
}
