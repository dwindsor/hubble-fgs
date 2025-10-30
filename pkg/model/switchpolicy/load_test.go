package switchpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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

func (m *mockPolicyHandler) ListPolicies() map[ResourceID]K8sRulesList {
	return m.policies
}

func (m *mockPolicyHandler) UpsertPolicy(resourceId ResourceID, rules K8sRulesList) error {
	m.upsertCalled = true
	m.upsertCounter++
	if m.upsertError != nil {
		return m.upsertError
	}
	m.policies[resourceId] = rules
	return nil
}

func (m *mockPolicyHandler) DeletePolicy(resourceId ResourceID) error {
	m.deleteCalled = true
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.policies, resourceId)
	return nil
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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
          - protocol: tcp
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

// var emptyProtoPortsYAML = `
// apiVersion: isovalent.com/v1alpha1
// kind: SmartSwitchNetworkPolicy
// metadata:
//   name: empty-protoports
//   namespace: default
// spec:
//   rules:
//     - action: allow
//       source:
//         ipBlock:
//           - cidr: 10.0.0.0/8
//       destination:
//         ipBlock:
//           - cidr: 192.168.1.0/24
//         protoPorts: []
// `

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
		// FIXME: validation needs to be added to CRD definition
		// {
		// 	name:    "Empty protoPorts array should fail validation",
		// 	yaml:    emptyProtoPortsYAML,
		// 	wantNil: false,
		// 	wantErr: true,
		// },
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
				require.Equal(t, uint32(100), policies[0].Spec.Rules[0].Source.IPBlock[0].VLAN)
				require.Equal(t, uint32(200), policies[0].Spec.Rules[0].Destination.IPBlock[0].VLAN)

				// Check second policy (VRF policy)
				require.Equal(t, "network-policy-l3", policies[1].Name)
				require.Equal(t, "default", policies[1].Namespace)
				require.Len(t, policies[1].Spec.Rules, 1)
				require.Equal(t, "allow", policies[1].Spec.Rules[0].Action)
				require.Equal(t, "default", policies[1].Spec.Rules[0].Source.IPBlock[0].VRF)
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8", VRF: "internal"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24", VRF: "external"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
								},
							},
						},
						{
							Action: "deny",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "172.16.0.0/12"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.2.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 80},
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
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
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 443},
								},
							},
						},
						{
							Action: "deny",
							Source: v1alpha1.SmartSwitchNetworkSource{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "172.16.0.0/12"},
								},
							},
							Destination: v1alpha1.SmartSwitchNetworkDestination{
								IPBlock: []v1alpha1.SmartSwitchNetwork{
									{CIDR: "192.168.2.0/24"},
								},
								ProtoPorts: []v1alpha1.SmartSwitchProtocolPort{
									{Protocol: "tcp", Port: 80},
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
