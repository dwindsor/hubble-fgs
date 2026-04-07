// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

// Mock PolicyHandler for testing
type mockPolicyHandler struct {
	upsertCalled  bool
	deleteCalled  bool
	upsertError   error
	deleteError   error
	policies      map[ResourceID]K8sRulesList
	upsertCounter int
}

func newMockPolicyHandler() *mockPolicyHandler {
	return &mockPolicyHandler{
		policies: make(map[ResourceID]K8sRulesList),
	}
}

func (m *mockPolicyHandler) SetL3Networks(_ *L3Networks) error {
	return nil
}

func (m *mockPolicyHandler) GetL3Networks() *L3Networks {
	return NewL3Networks()
}

func (m *mockPolicyHandler) ListPolicies() map[ResourceID]K8sRulesList {
	return m.policies
}

func (m *mockPolicyHandler) UpsertPolicy(resourceId ResourceID, rules K8sRulesList, _ string) error {
	m.upsertCalled = true
	m.upsertCounter++
	if m.upsertError != nil {
		return m.upsertError
	}
	m.policies[resourceId] = rules
	return nil
}

func (m *mockPolicyHandler) DeletePolicy(resourceId ResourceID, _ string) error {
	m.deleteCalled = true
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.policies, resourceId)
	return nil
}

func (m *mockPolicyHandler) ResourceVersion() (string, error) {
	return "", nil
}

var validMultiPolicy = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: vlan-policy
  namespace: test-ns
spec:
  rules:
    - action: deny
      description: "Deny VLAN traffic"
      source:
        ipBlock:
          - cidr: 192.168.1.0/24
            vlan: 100
      destination:
        ipBlock:
          - cidr: 192.168.2.0/24
            vlan: 200
        protoPorts:
          - protocol: TCP
            port: 8080
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: network-policy-l3
  namespace: default
spec:
  rules:
    - action: allow
      description: "Allow All routed IPV4 traffic default"
      source:
        ipBlock:
          - cidr: 0.0.0.0/0
            vrf: default
      destination:
        ipBlock:
          - cidr: 0.0.0.0/0
        protoPorts:
          - protocol: TCP
            port: 8080
`

var validMultiPolicyWithEmpties = `
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: vlan-policy
  namespace: test-ns
spec:
  rules:
    - action: deny
      description: "Deny VLAN traffic"
      source:
        ipBlock:
          - cidr: 192.168.1.0/24
            vlan: 100
      destination:
        ipBlock:
          - cidr: 192.168.2.0/24
            vlan: 200
        protoPorts:
          - protocol: TCP
            port: 8080
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: network-policy-l3
  namespace: default
spec:
  rules:
    - action: allow
      description: "Allow All routed IPV4 traffic default"
      source:
        ipBlock:
          - cidr: 0.0.0.0/0
            vrf: default
      destination:
        ipBlock:
          - cidr: 0.0.0.0/0
        protoPorts:
          - protocol: TCP
            port: 8080
---
---
`

var validPolicyWithVRF = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: network-policy-l3
  namespace: default
spec:
  rules:
    - action: allow
      description: "Allow All routed IPV4 traffic default"
      source:
        ipBlock:
          - cidr: 0.0.0.0/0
            vrf: default
      destination:
        ipBlock:
          - cidr: 0.0.0.0/0
        protoPorts:
          - protocol: TCP
            port: 8080
`

var validPolicyWithVLAN = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: vlan-policy
  namespace: test-ns
spec:
  rules:
    - action: deny
      description: "Deny VLAN traffic"
      source:
        ipBlock:
          - cidr: 192.168.1.0/24
            vlan: 100
      destination:
        ipBlock:
          - cidr: 192.168.2.0/24
            vlan: 200
        protoPorts:
          - protocol: TCP
            port: 8080
`

var validPolicyWithVRFAndVLAN = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: network-policy-l3
  namespace: default
spec:
  rules:
    - action: allow
      description: "Allow All routed IPV4 traffic default"
      source:
        ipBlock:
          - cidr: 0.0.0.0/0
            vrf: default
            vlan: 101
      destination:
        ipBlock:
          - cidr: 0.0.0.0/0
        protoPorts:
          - protocol: TCP
            port: 8080
`

var invalidYAMLSyntax = `
this is not: valid YAML {[}]
metadata: :::
`

var wrongKindYAML = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: some-config
data:
  key: value
`

var missingMetadataYAML = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts:
          - protocol: TCP
`

var missingSpecYAML = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: no-spec
  namespace: default
`

var emptyRulesYAML = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: empty-rules
  namespace: default
spec:
  rules: []
`

var missingProtoPortsYAML = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: no-protoports
  namespace: default
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
`

var emptyProtoPortsYAML = `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: empty-protoports
  namespace: default
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts: []
`

func TestFromYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "Valid policy with VRF",
			yaml:    validPolicyWithVRF,
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "Valid policy with VLAN",
			yaml:    validPolicyWithVLAN,
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "Valid policy with VRF and VLAN",
			yaml:    validPolicyWithVRFAndVLAN,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Empty rules list",
			yaml:    emptyRulesYAML,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Wrong kind returns nil without error",
			yaml:    wrongKindYAML,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Invalid YAML syntax",
			yaml:    invalidYAMLSyntax,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Empty string",
			yaml:    "",
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Missing metadata should fail validation",
			yaml:    missingMetadataYAML,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Missing spec should fail validation",
			yaml:    missingSpecYAML,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Missing protoPorts should fail validation",
			yaml:    missingProtoPortsYAML,
			wantNil: false,
			wantErr: true,
		},
		{
			name:    "Multi-policy document parses first policy",
			yaml:    validMultiPolicy,
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "Empty protoPorts array should fail validation",
			yaml:    emptyProtoPortsYAML,
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromYAML(tt.yaml)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if tt.wantNil {
				require.Nil(t, got, "Expected nil policy")
			} else if !tt.wantErr {
				require.NotNil(t, got, "Expected non-nil policy")
			}
		})
	}
}

func TestFromYAMLMultiplePolicies(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		wantErr       bool
		expectedCount int
		checkPolicies func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy)
	}{
		{
			name:          "Multiple policies document parses all policies",
			yaml:          validMultiPolicy,
			wantErr:       false,
			expectedCount: 2,
			checkPolicies: func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy) {
				require.Len(t, policies, 2, "Expected 2 policies to be parsed")

				// Check first policy (VLAN policy)
				require.Equal(t, "vlan-policy", policies[0].Name)
				require.Equal(t, "test-ns", policies[0].Namespace)
				require.Len(t, policies[0].Spec.Rules, 1)
				require.Equal(t, "deny", policies[0].Spec.Rules[0].Action)
				require.Equal(t, int32(100), policies[0].Spec.Rules[0].Source.IPBlock[0].VLAN)      //nolint:staticcheck
				require.Equal(t, int32(200), policies[0].Spec.Rules[0].Destination.IPBlock[0].VLAN) //nolint:staticcheck

				// Check second policy (VRF policy)
				require.Equal(t, "network-policy-l3", policies[1].Name)
				require.Equal(t, "default", policies[1].Namespace)
				require.Len(t, policies[1].Spec.Rules, 1)
				require.Equal(t, "allow", policies[1].Spec.Rules[0].Action)
				require.Equal(t, "default", policies[1].Spec.Rules[0].Source.IPBlock[0].VRF) //nolint:staticcheck
			},
		},
		{
			name:          "Multiple policies with empty documents",
			yaml:          validMultiPolicyWithEmpties,
			wantErr:       false,
			expectedCount: 2,
			checkPolicies: func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy) {
				require.Len(t, policies, 2, "Expected 2 policies to be parsed (empty documents should be skipped)")

				// Verify both policies are present
				require.Equal(t, "vlan-policy", policies[0].Name)
				require.Equal(t, "network-policy-l3", policies[1].Name)
			},
		},
		{
			name:          "Single policy returns one policy",
			yaml:          validPolicyWithVRF,
			wantErr:       false,
			expectedCount: 1,
			checkPolicies: func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy) {
				require.Len(t, policies, 1, "Expected 1 policy to be parsed")
				require.Equal(t, "network-policy-l3", policies[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromYAML(tt.yaml)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
				require.NotNil(t, got, "Expected non-nil policies slice")
				require.Len(t, got, tt.expectedCount, "Expected %d policies but got %d", tt.expectedCount, len(got))

				if tt.checkPolicies != nil {
					tt.checkPolicies(t, got)
				}
			}
		})
	}
}

func TestFromFileMultiplePolicies(t *testing.T) {
	tests := []struct {
		name          string
		setupFile     func(t *testing.T) string
		wantErr       bool
		expectedCount int
		checkPolicies func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy)
	}{
		{
			name: "File with multiple policies",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicy)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr:       false,
			expectedCount: 2,
			checkPolicies: func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy) {
				require.Len(t, policies, 2, "Expected 2 policies to be parsed from file")
				require.Equal(t, "vlan-policy", policies[0].Name)
				require.Equal(t, "network-policy-l3", policies[1].Name)
			},
		},
		{
			name: "File with multiple policies and empty documents",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-empty-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicyWithEmpties)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr:       false,
			expectedCount: 2,
			checkPolicies: func(t *testing.T, policies []*v1alpha1.SmartSwitchNetworkPolicy) {
				require.Len(t, policies, 2, "Expected 2 policies (empty documents should be skipped)")
				require.Equal(t, "vlan-policy", policies[0].Name)
				require.Equal(t, "network-policy-l3", policies[1].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			got, err := FromFile(path)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
				require.NotNil(t, got, "Expected non-nil policies slice")
				require.Len(t, got, tt.expectedCount, "Expected %d policies but got %d", tt.expectedCount, len(got))

				if tt.checkPolicies != nil {
					tt.checkPolicies(t, got)
				}
			}
		})
	}
}

func TestFromFile(t *testing.T) {
	tests := []struct {
		name      string
		setupFile func(t *testing.T) string
		wantErr   bool
		wantNil   bool
	}{
		{
			name: "Valid policy file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validPolicyWithVRF)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name: "Invalid YAML in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-invalid-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(invalidYAMLSyntax)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr: true,
			wantNil: false,
		},
		{
			name: "File not found",
			setupFile: func(_ *testing.T) string {
				return "/nonexistent/path/to/file.yaml"
			},
			wantErr: true,
			wantNil: false,
		},
		{
			name: "Empty file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-empty-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr: true,
			wantNil: false,
		},
		{
			name: "File with relative path",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "policy.yaml")
				err := os.WriteFile(filePath, []byte(validPolicyWithVRF), 0644)
				require.NoError(t, err)
				oldDir, err := os.Getwd()
				require.NoError(t, err)
				t.Cleanup(func() { os.Chdir(oldDir) })
				err = os.Chdir(tmpDir)
				require.NoError(t, err)
				return "policy.yaml"
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name: "Wrong kind in file returns nil",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-wrongkind-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(wrongKindYAML)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr: true,
			wantNil: false,
		},
		{
			name: "File with missing protoPorts",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-noports-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(missingProtoPortsYAML)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			wantErr: true,
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			got, err := FromFile(path)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if tt.wantNil {
				require.Nil(t, got, "Expected nil policy")
			} else if !tt.wantErr {
				require.NotNil(t, got, "Expected non-nil policy")
			}
		})
	}
}

func TestAddFromYAML(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkUpsert  bool
	}{
		{
			name: "Successfully add valid policy",
			yaml: validPolicyWithVRF,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkUpsert: true,
		},
		{
			name: "Successfully add policy with VLAN",
			yaml: validPolicyWithVLAN,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkUpsert: true,
		},
		{
			name: "Fail on invalid YAML",
			yaml: invalidYAMLSyntax,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Fail on wrong kind",
			yaml: wrongKindYAML,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Fail when handler returns error",
			yaml: validPolicyWithVRF,
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.upsertError = fmt.Errorf("handler error")
				return m
			},
			wantErr:     true,
			checkUpsert: true,
		},
		{
			name: "Fail on missing protoPorts",
			yaml: missingProtoPortsYAML,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		// FIXME: needs to be added to validation in CRD
		// {
		// 	name: "Fail on empty protoPorts",
		// 	yaml: emptyProtoPortsYAML,
		// 	setupHandler: func() *mockPolicyHandler {
		// 		return newMockPolicyHandler()
		// 	},
		// 	wantErr:     true,
		// 	checkUpsert: false,
		// },
		{
			name: "Empty string",
			yaml: "",
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Empty rules list is invalid",
			yaml: emptyRulesYAML,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()
			err := AddFromYAML(tt.yaml, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if tt.checkUpsert {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				if !tt.wantErr {
					// Verify policy was actually added to the handler
					require.NotEmpty(t, handler.policies, "Expected policies to be added to handler")
					// Verify at least one policy rule was added
					var totalRules int
					for _, rules := range handler.policies {
						totalRules += len(rules)
					}
					require.Greater(t, totalRules, 0, "Expected at least one policy rule to be added")
				}
			} else {
				require.False(t, handler.upsertCalled, "Expected UpsertPolicy not to be called")
				require.Empty(t, handler.policies, "Expected no policies to be added")
			}
		})
	}
}

func TestAddFromYAMLMultiplePolicies(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		setupHandler     func() *mockPolicyHandler
		wantErr          bool
		expectedPolicies int
		checkHandler     func(t *testing.T, handler *mockPolicyHandler)
	}{
		{
			name: "Successfully add all policies from multi-policy document",
			yaml: validMultiPolicy,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:          false,
			expectedPolicies: 2,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				require.Len(t, handler.policies, 2, "Expected 2 policies to be added to handler")

				// Verify both policies were added by checking their resource IDs
				var foundVLANPolicy, foundVRFPolicy bool
				for resourceID := range handler.policies {
					if resourceID.name == "vlan-policy" && resourceID.namespace == "test-ns" {
						foundVLANPolicy = true
					}
					if resourceID.name == "network-policy-l3" && resourceID.namespace == "default" {
						foundVRFPolicy = true
					}
				}
				require.True(t, foundVLANPolicy, "Expected vlan-policy to be added")
				require.True(t, foundVRFPolicy, "Expected network-policy-l3 to be added")

				// Verify total rules added
				var totalRules int
				for _, rules := range handler.policies {
					totalRules += len(rules)
				}
				require.Greater(t, totalRules, 0, "Expected policy rules to be added")
			},
		},
		{
			name: "Successfully add all policies with empty documents",
			yaml: validMultiPolicyWithEmpties,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:          false,
			expectedPolicies: 2,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				require.Len(t, handler.policies, 2, "Expected 2 policies (empty documents should be skipped)")

				var foundVLANPolicy, foundVRFPolicy bool
				for resourceID := range handler.policies {
					if resourceID.name == "vlan-policy" {
						foundVLANPolicy = true
					}
					if resourceID.name == "network-policy-l3" {
						foundVRFPolicy = true
					}
				}
				require.True(t, foundVLANPolicy, "Expected vlan-policy to be added")
				require.True(t, foundVRFPolicy, "Expected network-policy-l3 to be added")
			},
		},
		{
			name: "Single policy added successfully",
			yaml: validPolicyWithVRF,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:          false,
			expectedPolicies: 1,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				require.Len(t, handler.policies, 1, "Expected 1 policy to be added")
				require.Equal(t, 1, handler.upsertCounter, "Expected UpsertPolicy to be called once")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()

			err := AddFromYAML(tt.yaml, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}

			if tt.checkHandler != nil {
				tt.checkHandler(t, handler)
			}
		})
	}
}

func TestAddFromFile(t *testing.T) {
	tests := []struct {
		name         string
		setupFile    func(t *testing.T) string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkUpsert  bool
	}{
		{
			name: "Successfully add policy from file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validPolicyWithVRF)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkUpsert: true,
		},
		{
			name: "File not found",
			setupFile: func(_ *testing.T) string {
				return "/nonexistent/file.yaml"
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Invalid YAML in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-invalid-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(invalidYAMLSyntax)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Wrong kind in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-wrongkind-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(wrongKindYAML)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkUpsert: false,
		},
		{
			name: "Handler returns error",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validPolicyWithVRF)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.upsertError = fmt.Errorf("upsert failed")
				return m
			},
			wantErr:     true,
			checkUpsert: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			handler := tt.setupHandler()
			err := AddFromFile(path, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if tt.checkUpsert {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				if !tt.wantErr {
					// Verify policy was actually added to the handler
					require.NotEmpty(t, handler.policies, "Expected policies to be added to handler")
					// Verify at least one policy rule was added
					var totalRules int
					for _, rules := range handler.policies {
						totalRules += len(rules)
					}
					require.Greater(t, totalRules, 0, "Expected at least one policy rule to be added")
				}
			} else {
				require.False(t, handler.upsertCalled, "Expected UpsertPolicy not to be called")
				require.Empty(t, handler.policies, "Expected no policies to be added")
			}
		})
	}
}

func TestAddFromFileMultiplePolicies(t *testing.T) {
	tests := []struct {
		name         string
		setupFile    func(t *testing.T) string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkHandler func(t *testing.T, handler *mockPolicyHandler)
	}{
		{
			name: "Successfully add all policies from multi-policy file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicy)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				require.Len(t, handler.policies, 2, "Expected 2 policies to be added from file")
				require.Equal(t, 2, handler.upsertCounter, "Expected UpsertPolicy to be called twice")

				// Verify both policies were added
				var foundVLANPolicy, foundVRFPolicy bool
				for resourceID := range handler.policies {
					if resourceID.name == "vlan-policy" && resourceID.namespace == "test-ns" {
						foundVLANPolicy = true
					}
					if resourceID.name == "network-policy-l3" && resourceID.namespace == "default" {
						foundVRFPolicy = true
					}
				}
				require.True(t, foundVLANPolicy, "Expected vlan-policy to be added")
				require.True(t, foundVRFPolicy, "Expected network-policy-l3 to be added")
			},
		},
		{
			name: "Successfully add all policies with empty documents in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-empty-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicyWithEmpties)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.upsertCalled, "Expected UpsertPolicy to be called")
				require.Len(t, handler.policies, 2, "Expected 2 policies (empty documents should be skipped)")
				require.Equal(t, 2, handler.upsertCounter, "Expected UpsertPolicy to be called twice")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			handler := tt.setupHandler()
			err := AddFromFile(path, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if tt.checkHandler != nil {
				tt.checkHandler(t, handler)
			}
		})
	}
}

func TestDeleteFromYAML(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkDelete  bool
	}{
		{
			name: "Successfully delete valid policy",
			yaml: validPolicyWithVRF,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkDelete: true,
		},
		{
			name: "Successfully delete policy with VLAN",
			yaml: validPolicyWithVLAN,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkDelete: true,
		},
		{
			name: "Fail on invalid YAML",
			yaml: invalidYAMLSyntax,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Fail on wrong kind",
			yaml: wrongKindYAML,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Fail when handler returns error",
			yaml: validPolicyWithVRF,
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.deleteError = fmt.Errorf("delete error")
				return m
			},
			wantErr:     true,
			checkDelete: true,
		},
		{
			name: "Empty string",
			yaml: "",
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Empty rules list doesn't allow delete",
			yaml: emptyRulesYAML,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()

			// Pre-populate handler with a policy if we expect successful deletion
			if tt.checkDelete && !tt.wantErr {
				// First add the policy
				addErr := AddFromYAML(tt.yaml, handler)
				require.NoError(t, addErr, "Failed to setup test by adding policy")
				require.NotEmpty(t, handler.policies, "Policy should exist before deletion")
				policiesBeforeDelete := len(handler.policies)

				// Reset the deleteCalled flag after add
				handler.deleteCalled = false

				// Now delete it
				err := DeleteFromYAML(tt.yaml, handler)
				require.NoError(t, err, "Unexpected error during deletion: %v", err)
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")

				// Verify policy was actually removed
				require.Less(t, len(handler.policies), policiesBeforeDelete, "Expected policy to be removed from handler")
			} else {
				// For error cases or non-delete cases
				err := DeleteFromYAML(tt.yaml, handler)
				if tt.wantErr {
					require.Error(t, err, "Expected error but got none")
				} else {
					require.NoError(t, err, "Unexpected error: %v", err)
				}
				if tt.checkDelete {
					require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				} else {
					require.False(t, handler.deleteCalled, "Expected DeletePolicy not to be called")
				}
			}
		})
	}
}

func TestDeleteFromYAMLMultiplePolicies(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkHandler func(t *testing.T, handler *mockPolicyHandler)
	}{
		{
			name: "Successfully delete all policies from multi-policy document",
			yaml: validMultiPolicy,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				require.Empty(t, handler.policies, "Expected all policies to be deleted")
			},
		},
		{
			name: "Successfully delete all policies with empty documents",
			yaml: validMultiPolicyWithEmpties,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				require.Empty(t, handler.policies, "Expected all policies to be deleted")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()

			// First add the policies
			addErr := AddFromYAML(tt.yaml, handler)
			require.NoError(t, addErr, "Failed to setup test by adding policies")
			policiesBeforeDelete := len(handler.policies)
			require.Greater(t, policiesBeforeDelete, 0, "Policies should exist before deletion")

			// Reset the deleteCalled flag after add
			handler.deleteCalled = false

			// Now delete them
			err := DeleteFromYAML(tt.yaml, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}

			if tt.checkHandler != nil {
				tt.checkHandler(t, handler)
			}
		})
	}
}

func TestDeleteFromFile(t *testing.T) {
	tests := []struct {
		name         string
		setupFile    func(t *testing.T) string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkDelete  bool
	}{
		{
			name: "Successfully delete policy from file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validPolicyWithVRF)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     false,
			checkDelete: true,
		},
		{
			name: "File not found",
			setupFile: func(_ *testing.T) string {
				return "/nonexistent/file.yaml"
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Invalid YAML in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-invalid-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(invalidYAMLSyntax)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Wrong kind in file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-wrongkind-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(wrongKindYAML)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr:     true,
			checkDelete: false,
		},
		{
			name: "Handler returns error",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validPolicyWithVRF)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.deleteError = fmt.Errorf("delete failed")
				return m
			},
			wantErr:     true,
			checkDelete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			handler := tt.setupHandler()

			// Pre-populate handler with a policy if we expect successful deletion
			if tt.checkDelete && !tt.wantErr {
				// First add the policy
				addErr := AddFromFile(path, handler)
				require.NoError(t, addErr, "Failed to setup test by adding policy")
				require.NotEmpty(t, handler.policies, "Policy should exist before deletion")
				policiesBeforeDelete := len(handler.policies)

				// Reset the deleteCalled flag after add
				handler.deleteCalled = false

				// Now delete it
				err := DeleteFromFile(path, handler)
				require.NoError(t, err, "Unexpected error during deletion: %v", err)
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")

				// Verify policy was actually removed
				require.Less(t, len(handler.policies), policiesBeforeDelete, "Expected policy to be removed from handler")
			} else {
				// For error cases or non-delete cases
				err := DeleteFromFile(path, handler)
				if tt.wantErr {
					require.Error(t, err, "Expected error but got none")
				} else {
					require.NoError(t, err, "Unexpected error: %v", err)
				}
				if tt.checkDelete {
					require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				} else {
					require.False(t, handler.deleteCalled, "Expected DeletePolicy not to be called")
				}
			}
		})
	}
}

func TestDeleteFromFileMultiplePolicies(t *testing.T) {
	tests := []struct {
		name         string
		setupFile    func(t *testing.T) string
		setupHandler func() *mockPolicyHandler
		wantErr      bool
		checkHandler func(t *testing.T, handler *mockPolicyHandler)
	}{
		{
			name: "Successfully delete all policies from multi-policy file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-policy-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicy)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				require.Empty(t, handler.policies, "Expected all policies to be deleted from file")
			},
		},
		{
			name: "Successfully delete all policies with empty documents from file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp("", "test-multi-empty-*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() { os.Remove(f.Name()) })
				_, err = f.WriteString(validMultiPolicyWithEmpties)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				return f.Name()
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
			checkHandler: func(t *testing.T, handler *mockPolicyHandler) {
				require.True(t, handler.deleteCalled, "Expected DeletePolicy to be called")
				require.Empty(t, handler.policies, "Expected all policies to be deleted")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			handler := tt.setupHandler()

			// First add the policies from the file
			addErr := AddFromFile(path, handler)
			require.NoError(t, addErr, "Failed to setup test by adding policies")
			policiesBeforeDelete := len(handler.policies)
			require.Greater(t, policiesBeforeDelete, 0, "Policies should exist before deletion")

			// Reset the deleteCalled flag after add
			handler.deleteCalled = false

			// Now delete them
			err := DeleteFromFile(path, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}

			if tt.checkHandler != nil {
				tt.checkHandler(t, handler)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name         string
		policy       *v1alpha1.SmartSwitchNetworkPolicy
		setupHandler func() *mockPolicyHandler
		wantErr      bool
	}{
		{
			name: "Successfully add valid policy",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
		{
			name: "Handler returns error",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.upsertError = fmt.Errorf("handler error")
				return m
			},
			wantErr: true,
		},
		{
			name: "Policy with empty rules",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
		{
			name: "Policy with multiple rules",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8", VRF: "internal"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24", VRF: "external"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
						{
							Action: "deny",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "172.16.0.0/12"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.2.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 80},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()
			err := Add(tt.policy, handler)
			if tt.wantErr {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)

				// Verify policy was actually added (unless nil policy)
				if tt.policy != nil {
					require.NotEmpty(t, handler.policies, "Expected policies to be added to handler")

					// Verify rules were added based on the policy spec
					if len(tt.policy.Spec.Rules) > 0 {
						var totalRules int
						for _, rules := range handler.policies {
							totalRules += len(rules)
						}
						require.Greater(t, totalRules, 0, "Expected policy rules to be added")
					}
				} else {
					// Nil policy should not add anything
					require.Empty(t, handler.policies, "Nil policy should not add any policies")
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name         string
		policy       *v1alpha1.SmartSwitchNetworkPolicy
		setupHandler func() *mockPolicyHandler
		wantErr      bool
	}{
		{
			name: "Successfully delete valid policy",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
		{
			name:   "Nil policy returns nil without error",
			policy: nil,
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
		{
			name: "Handler returns error",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				m := newMockPolicyHandler()
				m.deleteError = fmt.Errorf("delete error")
				return m
			},
			wantErr: true,
		},
		{
			name: "Delete policy with multiple rules",
			policy: &v1alpha1.SmartSwitchNetworkPolicy{
				Spec: v1alpha1.SmartSwitchNetworkPolicySpec{
					Rules: []v1alpha1.SmartSwitchNetworkPolicyRule{
						{
							Action: "allow",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 443},
								},
							},
						},
						{
							Action: "deny",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "172.16.0.0/12"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.NetworkObjectGroupSpec{
									{CIDR: "192.168.2.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "TCP", Port: 80},
								},
							},
						},
					},
				},
			},
			setupHandler: func() *mockPolicyHandler {
				return newMockPolicyHandler()
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupHandler()

			// Pre-populate handler with the policy if not nil and not expecting error
			if tt.policy != nil && !tt.wantErr {
				// First add the policy
				addErr := Add(tt.policy, handler)
				require.NoError(t, addErr, "Failed to setup test by adding policy")

				// Verify it was added
				require.NotEmpty(t, handler.policies, "Policy should exist before deletion")
				policiesCountBefore := len(handler.policies)

				// Now delete it
				err := Delete(tt.policy, handler)
				require.NoError(t, err, "Unexpected error during deletion: %v", err)

				// Verify policy was actually removed
				require.Less(t, len(handler.policies), policiesCountBefore, "Expected policy count to decrease after deletion")
			} else {
				// For nil policy or error cases
				err := Delete(tt.policy, handler)
				if tt.wantErr {
					require.Error(t, err, "Expected error but got none")
				} else {
					require.NoError(t, err, "Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCleanK8sMetadata(t *testing.T) {
	now := metav1.Now()
	gracePeriod := int64(30)
	uid := "test-uid-12345"
	tests := []struct {
		name     string
		meta     *metav1.ObjectMeta
		validate func(t *testing.T, meta *metav1.ObjectMeta)
	}{
		{
			name: "Removes all internal Kubernetes fields",
			meta: &metav1.ObjectMeta{
				Name:                       "test-policy",
				Namespace:                  "test-ns",
				UID:                        "test-uid-12345",
				ResourceVersion:            "12345",
				Generation:                 5,
				CreationTimestamp:          now,
				DeletionTimestamp:          &now,
				DeletionGracePeriodSeconds: &gracePeriod,
				Labels: map[string]string{
					"app": "test",
				},
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": `{"some":"config"}`,
					"user-annotation": "keep-me",
				},
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply},
				},
				OwnerReferences: []metav1.OwnerReference{
					{Name: "owner", Kind: "Deployment"},
				},
				Finalizers: []string{"finalizer1", "finalizer2"},
			},
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				// Verify internal fields are cleared
				require.Empty(t, meta.UID, "UID should be empty")
				require.Empty(t, meta.ResourceVersion, "ResourceVersion should be empty")
				require.Zero(t, meta.Generation, "Generation should be zero")
				require.True(t, meta.CreationTimestamp.IsZero(), "CreationTimestamp should be zero")
				require.Nil(t, meta.DeletionTimestamp, "DeletionTimestamp should be nil")
				require.Nil(t, meta.DeletionGracePeriodSeconds, "DeletionGracePeriodSeconds should be nil")
				require.Nil(t, meta.ManagedFields, "ManagedFields should be nil")
				require.Nil(t, meta.OwnerReferences, "OwnerReferences should be nil")
				require.Nil(t, meta.Finalizers, "Finalizers should be nil")
				// Verify user fields are preserved
				require.Equal(t, "test-policy", meta.Name, "Name should be preserved")
				require.Equal(t, "test-ns", meta.Namespace, "Namespace should be preserved")
				require.Equal(t, "test", meta.Labels["app"], "Labels should be preserved")
				// Verify annotations are cleaned correctly
				require.NotContains(t, meta.Annotations, "kubectl.kubernetes.io/last-applied-configuration",
					"kubectl last-applied-configuration annotation should be removed")
				require.Equal(t, "keep-me", meta.Annotations["user-annotation"],
					"User annotations should be preserved")
			},
		},
		{
			name: "Handles nil ObjectMeta gracefully",
			meta: nil,
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				// Should not panic, meta remains nil
				require.Nil(t, meta)
			},
		},
		{
			name: "Handles empty ObjectMeta",
			meta: &metav1.ObjectMeta{},
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				require.NotNil(t, meta)
				require.Empty(t, meta.UID)
				require.Empty(t, meta.ResourceVersion)
				require.Zero(t, meta.Generation)
			},
		},
		{
			name: "Preserves user metadata without internal fields",
			meta: &metav1.ObjectMeta{
				Name:      "policy-name",
				Namespace: "default",
				Labels: map[string]string{
					"env":  "prod",
					"team": "platform",
				},
				Annotations: map[string]string{
					"description": "My policy description",
				},
			},
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				require.Equal(t, "policy-name", meta.Name)
				require.Equal(t, "default", meta.Namespace)
				require.Equal(t, "prod", meta.Labels["env"])
				require.Equal(t, "platform", meta.Labels["team"])
				require.Equal(t, "My policy description", meta.Annotations["description"])
				require.Empty(t, meta.UID)
				require.Empty(t, meta.ResourceVersion)
			},
		},
		{
			name: "Removes kubectl annotation but preserves other annotations",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1"}`,
					"custom-annotation-1":                              "value1",
					"custom-annotation-2":                              "value2",
				},
			},
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				require.NotContains(t, meta.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
				require.Equal(t, "value1", meta.Annotations["custom-annotation-1"])
				require.Equal(t, "value2", meta.Annotations["custom-annotation-2"])
				require.Len(t, meta.Annotations, 2, "Should have 2 annotations after cleanup")
			},
		},
		{
			name: "Handles annotations being nil",
			meta: &metav1.ObjectMeta{
				Name:        "test",
				UID:         types.UID(uid),
				Annotations: nil,
			},
			validate: func(t *testing.T, meta *metav1.ObjectMeta) {
				require.Empty(t, meta.UID)
				require.Nil(t, meta.Annotations)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanK8sMetadata(tt.meta)
			tt.validate(t, tt.meta)
		})
	}
}
func TestFromYAMLCleansMetadata(t *testing.T) {
	policyWithK8sMetadata := `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: test-policy
  namespace: default
  uid: "some-uid-12345"
  resourceVersion: "67890"
  generation: 3
  creationTimestamp: "2024-01-01T00:00:00Z"
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"isovalent.com/v1alpha1","kind":"SmartSwitchNetworkPolicy"}
    user-annotation: "should-be-kept"
  labels:
    app: myapp
spec:
  rules:
    - action: allow
      description: "Test rule"
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts:
          - protocol: TCP
            port: 443
`
	policies, err := FromYAML(policyWithK8sMetadata)
	require.NoError(t, err, "Failed to parse policy with K8s metadata")
	require.Len(t, policies, 1, "Expected 1 policy")
	policy := policies[0]
	// Verify internal K8s fields are removed
	require.Empty(t, policy.UID, "UID should be removed")
	require.Empty(t, policy.ResourceVersion, "ResourceVersion should be removed")
	require.Zero(t, policy.Generation, "Generation should be zero")
	require.True(t, policy.CreationTimestamp.IsZero(), "CreationTimestamp should be zero")
	require.Nil(t, policy.DeletionTimestamp, "DeletionTimestamp should be nil")
	require.Nil(t, policy.ManagedFields, "ManagedFields should be nil")
	require.Nil(t, policy.OwnerReferences, "OwnerReferences should be nil")
	// Verify kubectl annotation is removed
	require.NotContains(t, policy.Annotations, "kubectl.kubernetes.io/last-applied-configuration",
		"kubectl annotation should be removed")
	// Verify user metadata is preserved
	require.Equal(t, "test-policy", policy.Name, "Name should be preserved")
	require.Equal(t, "default", policy.Namespace, "Namespace should be preserved")
	require.Equal(t, "should-be-kept", policy.Annotations["user-annotation"],
		"User annotations should be preserved")
	require.Equal(t, "myapp", policy.Labels["app"], "Labels should be preserved")
}
func TestFromYAMLMultiplePoliciesCleansAllMetadata(t *testing.T) {
	multiPolicyWithMetadata := `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: policy1
  namespace: ns1
  uid: "uid-1"
  resourceVersion: "100"
  generation: 1
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"some":"config"}'
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts:
          - protocol: TCP
            port: 80
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: policy2
  namespace: ns2
  uid: "uid-2"
  resourceVersion: "200"
  generation: 2
  managedFields:
    - manager: kubectl
      operation: Apply
spec:
  rules:
    - action: deny
      source:
        ipBlock:
          - cidr: 172.16.0.0/12
      destination:
        ipBlock:
          - cidr: 192.168.2.0/24
        protoPorts:
          - protocol: TCP
            port: 443
`
	policies, err := FromYAML(multiPolicyWithMetadata)
	require.NoError(t, err)
	require.Len(t, policies, 2)
	// Verify all policies have metadata cleaned
	for i, policy := range policies {
		t.Run(fmt.Sprintf("Policy %d", i+1), func(t *testing.T) {
			require.Empty(t, policy.UID, "UID should be removed")
			require.Empty(t, policy.ResourceVersion, "ResourceVersion should be removed")
			require.Zero(t, policy.Generation, "Generation should be zero")
			require.Nil(t, policy.ManagedFields, "ManagedFields should be nil")
			require.NotContains(t, policy.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
		})
	}
}
func TestFromFileCleansMetadata(t *testing.T) {
	policyWithMetadata := `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: file-policy
  namespace: test-ns
  uid: "file-uid-123"
  resourceVersion: "999"
  finalizers:
    - finalizer.isovalent.com
  ownerReferences:
    - name: owner
      apiVersion: v1
      kind: Deployment
      uid: 123
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
            vrf: default
      destination:
        ipBlock:
          - cidr: 0.0.0.0/0
        protoPorts:
          - protocol: TCP
            port: 8080
`
	f, err := os.CreateTemp("", "test-metadata-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })
	_, err = f.WriteString(policyWithMetadata)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	policies, err := FromFile(f.Name())
	require.NoError(t, err)
	require.Len(t, policies, 1)
	policy := policies[0]
	// Verify metadata is cleaned
	require.Empty(t, policy.UID)
	require.Empty(t, policy.ResourceVersion)
	require.Nil(t, policy.Finalizers, "Finalizers should be removed")
	require.Nil(t, policy.OwnerReferences, "OwnerReferences should be removed")
	// Verify user fields preserved
	require.Equal(t, "file-policy", policy.Name)
	require.Equal(t, "test-ns", policy.Namespace)
}
