// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agw

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/ipc"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	"github.com/isovalent/hubble-fgs/pkg/token"
)

// --- Tests for validateLogConfig ---

func TestValidateLogConfigValidAndInvalidCases(t *testing.T) {
	cases := []struct {
		name   string
		cfg    LogConfigData
		errMsg string
	}{
		{
			name: "Valid config - TCP",
			cfg: LogConfigData{
				Id:   "id1",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "514",
					Proto: "tcp",
				},
			},
			errMsg: "",
		},
		{
			name: "Valid config - UDP",
			cfg: LogConfigData{
				Id:   "id2",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "192.168.1.1",
					Port:  "1514",
					Proto: "udp",
				},
			},
			errMsg: "",
		},
		{
			name: "Invalid host",
			cfg: LogConfigData{
				Id:   "id3",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "not-an-ip",
					Port:  "514",
					Proto: "tcp",
				},
			},
			errMsg: "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Invalid port (non-numeric)",
			cfg: LogConfigData{
				Id:   "id4",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "abc",
					Proto: "tcp",
				},
			},
			errMsg: "invalid port: must be a valid integer",
		},
		{
			name: "Invalid port (out of range)",
			cfg: LogConfigData{
				Id:   "id5",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "70000",
					Proto: "tcp",
				},
			},
			errMsg: "invalid port: must be between 1 and 65535",
		},
		{
			name: "Invalid mode",
			cfg: LogConfigData{
				Id:   "id6",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "514",
					Proto: "foo",
				},
			},
			errMsg: "invalid protocol: must be 'tcp' or 'udp'",
		},
		{
			name: "Empty type",
			cfg: LogConfigData{
				Id:   "id7",
				Type: "",
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "514",
					Proto: "tcp",
				},
			},
			errMsg: "log type is required",
		},
		{
			name: "Empty host",
			cfg: LogConfigData{
				Id:   "id8",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "",
					Port:  "514",
					Proto: "tcp",
				},
			},
			errMsg: "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Empty port",
			cfg: LogConfigData{
				Id:   "id9",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "",
					Proto: "tcp",
				},
			},
			errMsg: "invalid port: must be a valid integer",
		},
		{
			name: "Empty protocol",
			cfg: LogConfigData{
				Id:   "id10",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host:  "127.0.0.1",
					Port:  "514",
					Proto: "",
				},
			},
			errMsg: "log protocol is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateLogConfig(tc.cfg.Id, tc.cfg)
			if tc.errMsg == "" {
				require.NoError(t, err, "expected no error, got: %v", err)
			} else {
				require.Error(t, err, "expected error but got nil")
				require.EqualError(t, err, tc.errMsg)
			}
		})
	}
}

// --- Test for LoadSyslog with empty list ---

func TestLoadSyslogCases(t *testing.T) {
	agw := &AgentGateway{}
	cases := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "Empty list",
			input:     "{}",
			expectErr: false,
			errMsg:    "",
		},
		{
			name:      "Invalid JSON",
			input:     "{invalid}",
			expectErr: true,
			errMsg:    "invalid character",
		},
		{
			name: "Valid single syslog config",
			input: `{
				"sys1": {
					"id": "sys1",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: false,
			errMsg:    "",
		},
		{
			name: "Valid syslog config with UDP",
			input: `{
				"sys2": {
					"id": "sys2",
					"type": "syslog",
					"config": {
						"host": "192.168.1.1",
						"port": "1514",
						"protocol": "udp"
					},
					"secrets": {}
				}
			}`,
			expectErr: false,
			errMsg:    "",
		},
		{
			name: "Invalid type",
			input: `{
				"sys3": {
					"id": "sys3",
					"type": "unknown",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "log type is invalid",
		},
		{
			name: "Missing type",
			input: `{
				"sys4": {
					"id": "sys4",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "log type is required",
		},
		{
			name: "Invalid host",
			input: `{
				"sys5": {
					"id": "sys5",
					"type": "syslog",
					"config": {
						"host": "not-an-ip",
						"port": "514",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Invalid port (non-numeric)",
			input: `{
				"sys6": {
					"id": "sys6",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "abc",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid port: must be a valid integer",
		},
		{
			name: "Invalid port (out of range)",
			input: `{
				"sys7": {
					"id": "sys7",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "70000",
						"protocol": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid port: must be between 1 and 65535",
		},
		{
			name: "Invalid mode",
			input: `{
				"sys8": {
					"id": "sys8",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"protocol": "foo"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid protocol: must be 'tcp' or 'udp'",
		},
		{
			name:      "Empty config object",
			input:     "",
			expectErr: true,
			errMsg:    "unexpected end of JSON input",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := agw.LoadSyslog(context.Background(), tc.input)
			if tc.expectErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					require.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- Test for ShowSyslog ---
func TestShowSyslogNoConfig(t *testing.T) {
	agw := &AgentGateway{}
	// Ensure config is deleted before testing
	_ = agw.LoadSyslog(context.Background(), "{}")
	out, err := agw.ShowSyslog(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "log config not found")
	require.Empty(t, out)
}

func TestShowSyslogWithConfig(t *testing.T) {
	t.Run("Token Authentication", func(t *testing.T) {
		agw := &AgentGateway{}
		// Load a valid syslog config with token auth
		input := `{
			"sys1": {
				"id": "sys1",
				"type": "syslog",
				"config": {
					"host": "127.0.0.1",
					"port": "514",
					"protocol": "tcp"
				},
				"secrets": {
					"token": "tok"
				}
			}
		}`
		err := agw.LoadSyslog(context.Background(), input)
		require.NoError(t, err)
		out, err := agw.ShowSyslog(context.Background())
		require.NoError(t, err)
		require.Contains(t, out, `"host": "127.0.0.1"`)
		require.Contains(t, out, `"port": "514"`)
		require.Contains(t, out, `"token": "tok"`)
	})

	t.Run("Basic Authentication", func(t *testing.T) {
		agw := &AgentGateway{}
		// Load a valid syslog config with basic auth
		input := `{
			"sys2": {
				"id": "sys2",
				"type": "syslog",
				"config": {
					"host": "192.168.1.1",
					"port": "1514",
					"protocol": "udp"
				},
				"secrets": {
					"username": "user",
					"password": "pass"
				}
			}
		}`
		err := agw.LoadSyslog(context.Background(), input)
		require.NoError(t, err)
		out, err := agw.ShowSyslog(context.Background())
		require.NoError(t, err)
		require.Contains(t, out, `"host": "192.168.1.1"`)
		require.Contains(t, out, `"port": "1514"`)
		require.Contains(t, out, `"username": "user"`)
		require.Contains(t, out, `"password": "pass"`)
	})
}

func TestLoadSyslogDeleteConfig(t *testing.T) {
	agw := &AgentGateway{}
	// Load a valid config first
	input := `{
		"sys1": {
			"id": "sys1",
			"type": "syslog",
			"config": {
				"host": "127.0.0.1",
				"port": "514",
				"protocol": "tcp"
			},
			"secrets": {}
		}
	}`
	err := agw.LoadSyslog(context.Background(), input)
	require.NoError(t, err)
	// Now delete config by passing empty list
	err = agw.LoadSyslog(context.Background(), "{}")
	require.NoError(t, err)
	_, err = agw.ShowSyslog(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "log config not found")
}

// --- Test for ShowTokens ---

func TestShowTokens(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(*AgentGateway)
		expected string
	}{
		{
			name: "Empty tokens",
			setup: func(_ *AgentGateway) {
				// No setup, tokens should be empty
			},
			expected: "",
		},
		{
			name: "Single token",
			setup: func(agw *AgentGateway) {
				agw.Token = token.GetAgentToken()
				agw.Token.SetK8sAuthToken("token123")
			},
			expected: "k8s_controller_url=\nk8s_service_account=\nk8s_namespace=\nk8s_token=token123",
		},
		{
			name: "Multiple tokens",
			setup: func(agw *AgentGateway) {
				agw.Token = token.GetAgentToken()
				agw.Token.SetK8sAuthToken("tokenA,tokenB")
			},
			expected: "k8s_controller_url=\nk8s_service_account=\nk8s_namespace=\nk8s_token=tokenA,tokenB",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := &AgentGateway{}
			tc.setup(agw)
			token := agw.ShowTokens(context.Background())
			require.Equal(t, tc.expected, token)
		})
	}
}

// --- Test for Reopen ---

func TestReopen(t *testing.T) {
	agw := &AgentGateway{}
	result := agw.Reopen(context.Background())
	if result != "Reopen ok" {
		require.Equal(t, "Reopen ok", result)
	}
}

// --- Mock PolicyHandler for testing ---

type mockPolicyHandler struct {
	policies      map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
	deleteError   error
	deletedCalled []switchpolicy.ResourceID
}

func (m *mockPolicyHandler) ListPolicies() map[switchpolicy.ResourceID]switchpolicy.K8sRulesList {
	return m.policies
}

func (m *mockPolicyHandler) DeletePolicy(resourceId switchpolicy.ResourceID, _ string) error {
	m.deletedCalled = append(m.deletedCalled, resourceId)
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.policies, resourceId)
	return nil
}

func (m *mockPolicyHandler) UpsertPolicy(resourceId switchpolicy.ResourceID, rules switchpolicy.K8sRulesList, _ string) error {
	if m.policies == nil {
		m.policies = make(map[switchpolicy.ResourceID]switchpolicy.K8sRulesList)
	}
	m.policies[resourceId] = rules
	return nil
}

func (m *mockPolicyHandler) SetL3Networks(_ *switchpolicy.L3Networks) error {
	return nil
}

func (m *mockPolicyHandler) GetL3Networks() *switchpolicy.L3Networks {
	return switchpolicy.NewL3Networks()
}

func (m *mockPolicyHandler) ResourceVersion() (string, error) {
	return "", nil
}

// --- Test for PoliciesClear ---

func TestPoliciesClear(t *testing.T) {
	cases := []struct {
		name            string
		initialPolicies map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
		deleteError     error
		expectError     bool
		errorMsg        string
	}{
		{
			name: "Clear multiple policies successfully",
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "policy1"):     {},
				switchpolicy.NewResourceID("NetworkPolicy", "default", "policy2"):     {},
				switchpolicy.NewResourceID("NetworkPolicy", "kube-system", "policy3"): {},
			},
			deleteError: nil,
			expectError: false,
		},
		{
			name:            "Clear when no policies exist",
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			deleteError:     nil,
			expectError:     false,
		},
		{
			name: "Error during policy deletion",
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "failing-policy"): {},
			},
			deleteError: errors.New("failed to delete policy"),
			expectError: true,
			errorMsg:    "failed to delete policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock policy handler
			mockHandler := &mockPolicyHandler{
				policies:      tc.initialPolicies,
				deleteError:   tc.deleteError,
				deletedCalled: []switchpolicy.ResourceID{},
			}

			// Getting initial number of policies
			initialSize := len(tc.initialPolicies)

			// Create AgentGateway with mock handler
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			// Call PoliciesClear
			err := agw.PoliciesClear(context.Background())

			// Verify expectations
			if tc.expectError {
				require.Error(t, err)
				if tc.errorMsg != "" {
					require.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				require.NoError(t, err)
				// Verify all policies were attempted to be deleted
				require.Len(t, mockHandler.deletedCalled, initialSize)
				// Verify policies map is now empty (for success cases)
				require.Empty(t, mockHandler.policies)
			}
		})
	}
}

// --- Test for PoliciesAdd ---

func TestPoliciesAdd(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		setupFile      func(t *testing.T) string
		expectContains string
	}{
		{
			name: "Missing file flag",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			setupFile:      nil,
			expectContains: "Failed to add policies from file",
		},
		{
			name: "Non-existent file",
			msgData: ipc.MessageData{
				Flags: map[string]string{"file": "/nonexistent/path/policy.yaml"},
			},
			setupFile:      nil,
			expectContains: "Failed to add policies from file",
		},
		{
			name: "Empty file path",
			msgData: ipc.MessageData{
				Flags: map[string]string{"file": ""},
			},
			setupFile:      nil,
			expectContains: "Failed to add policies from file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockHandler := &mockPolicyHandler{
				policies: make(map[switchpolicy.ResourceID]switchpolicy.K8sRulesList),
			}
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			result := agw.PoliciesAdd(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

// --- Test for PoliciesRemove ---

func TestPoliciesRemove(t *testing.T) {
	cases := []struct {
		name            string
		msgData         ipc.MessageData
		initialPolicies map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
		expectContains  string
	}{
		{
			name: "Remove by valid resourceID",
			msgData: ipc.MessageData{
				Args:  []string{"NetworkPolicy/default/test-policy"},
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "test-policy"): {},
			},
			expectContains: "removed successfully",
		},
		{
			name: "Remove with invalid resourceID format",
			msgData: ipc.MessageData{
				Args:  []string{"invalid-format"},
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "invalid resourceID format",
		},
		{
			name: "Remove with two-part resourceID",
			msgData: ipc.MessageData{
				Args:  []string{"kind/name"},
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "invalid resourceID format",
		},
		{
			name: "Remove with non-existent file",
			msgData: ipc.MessageData{
				Args:  []string{},
				Flags: map[string]string{"file": "/nonexistent/path.yaml"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "Failed to remove policies from file",
		},
		{
			name: "Remove with empty args and no file",
			msgData: ipc.MessageData{
				Args:  []string{},
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "Failed to remove policies from file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockHandler := &mockPolicyHandler{
				policies: tc.initialPolicies,
			}
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			result := agw.PoliciesRemove(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

// --- Test for PoliciesShow ---

func TestPoliciesShow(t *testing.T) {
	cases := []struct {
		name            string
		msgData         ipc.MessageData
		initialPolicies map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
		expectContains  string
	}{
		{
			name: "Show empty policies - text",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "No policies",
		},
		{
			name: "Show empty policies - json",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "{}",
		},
		{
			name: "Show policies with filter - no match",
			msgData: ipc.MessageData{
				Flags: map[string]string{"filter": "nonexistent"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "test-policy"): {},
			},
			expectContains: "No policies",
		},
		{
			name: "Show policies with matching filter",
			msgData: ipc.MessageData{
				Flags: map[string]string{"filter": "test.*"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "test-policy"): {},
			},
			expectContains: "test-policy",
		},
		{
			name: "Show policies - json format",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "my-policy"): {},
			},
			expectContains: "my-policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockHandler := &mockPolicyHandler{
				policies: tc.initialPolicies,
			}
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			result := agw.PoliciesShow(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

// --- Test for PoliciesInfo ---

func TestPoliciesInfo(t *testing.T) {
	cases := []struct {
		name            string
		msgData         ipc.MessageData
		initialPolicies map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
		expectContains  string
	}{
		{
			name: "Info with no policies - text",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  "0",
		},
		{
			name: "Info with no policies - json",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{},
			expectContains:  `"total_policies":0`,
		},
		{
			name: "Info with policies - json",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "policy1"): {},
				switchpolicy.NewResourceID("NetworkPolicy", "default", "policy2"): {},
			},
			expectContains: `"total_policies":2`,
		},
		{
			name: "Info with policies in multiple namespaces - json",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			initialPolicies: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("NetworkPolicy", "default", "policy1"):     {},
				switchpolicy.NewResourceID("NetworkPolicy", "kube-system", "policy2"): {},
			},
			expectContains: `"policies_by_namespace"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockHandler := &mockPolicyHandler{
				policies: tc.initialPolicies,
			}
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			result := agw.PoliciesInfo(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

// --- Test for PoliciesTranslate ---

func TestPoliciesTranslate(t *testing.T) {
	cases := []struct {
		name        string
		msgData     ipc.MessageData
		setupFile   func(t *testing.T) string
		expectError bool
		errContains string
	}{
		{
			name: "Non-existent file",
			msgData: ipc.MessageData{
				Flags: map[string]string{"file": "/nonexistent/path/policy.yaml"},
			},
			setupFile:   nil,
			expectError: true,
			errContains: "failed to parse YAML file",
		},
		{
			name: "Empty YAML file",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "empty.yaml")
				err := os.WriteFile(filePath, []byte(""), 0644)
				require.NoError(t, err)
				return filePath
			},
			expectError: true,
			errContains: "failed to parse YAML file",
		},
		{
			name: "Invalid YAML file",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "invalid.yaml")
				err := os.WriteFile(filePath, []byte("{{invalid yaml"), 0644)
				require.NoError(t, err)
				return filePath
			},
			expectError: true,
			errContains: "failed to parse YAML file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockHandler := &mockPolicyHandler{
				policies: make(map[switchpolicy.ResourceID]switchpolicy.K8sRulesList),
			}
			agw := &AgentGateway{
				PolicyHandler: mockHandler,
			}

			msgData := tc.msgData
			if tc.setupFile != nil {
				filePath := tc.setupFile(t)
				msgData.Flags["file"] = filePath
			}

			result, err := agw.PoliciesTranslate(context.Background(), msgData)

			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, result)
			}
		})
	}
}

// --- Tests for GnmiShow methods ---

func createTestAgwWithNxosManager(_ *testing.T) *AgentGateway {
	ctx := context.Background()
	nxm := nxos.NewManager(ctx, nxos.WithMockGnmiHandler(nil))

	agw := &AgentGateway{
		nxosManager: nxm,
	}
	return agw
}

func TestGnmiShowVrf(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		expectContains string
	}{
		{
			name: "Text output",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "gNMI VRF Store",
		},
		{
			name: "JSON output",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"vrfs"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := createTestAgwWithNxosManager(t)
			result := agw.GnmiShowVrf(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

func TestGnmiShowVlan(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		expectContains string
	}{
		{
			name: "Text output",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "gNMI VLAN Store",
		},
		{
			name: "JSON output",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"vlans"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := createTestAgwWithNxosManager(t)
			result := agw.GnmiShowVlan(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

func TestGnmiShowDpu(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		expectContains string
	}{
		{
			name: "Text output",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "gNMI DPU Store",
		},
		{
			name: "JSON output",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"dpus"`,
		},
		{
			name: "JSON output contains count fields",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"count"`,
		},
		{
			name: "JSON output contains port fields",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"global_port_high"`,
		},
		{
			name: "JSON output contains in_sync",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"in_sync"`,
		},
		{
			name: "JSON output contains healthy",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"healthy"`,
		},
		{
			name: "JSON output contains in_sync_count",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"in_sync_count"`,
		},
		{
			name: "Text output contains In Sync",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "In Sync:",
		},
		{
			name: "JSON output contains global_port_low",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"global_port_low"`,
		},
		{
			name: "JSON output contains skip_dpu",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"skip_dpu"`,
		},
		{
			name: "Text output contains Global Port Range",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "Global Port Range:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := createTestAgwWithNxosManager(t)
			result := agw.GnmiShowDpu(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

func TestGnmiShowHa(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		expectContains string
	}{
		{
			name: "Text output contains header",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "gNMI HA Store",
		},
		{
			name: "Text output contains summary section",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "--- Summary ---",
		},
		{
			name: "Text output contains local state section",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "--- Local State ---",
		},
		{
			name: "Text output contains HA State field",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "HA State:",
		},
		{
			name: "Text output contains SVC State field",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "SVC State:",
		},
		{
			name: "Text output contains Adjacency Reached",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "Adjacency Reached:",
		},
		{
			name: "Text output contains Any Peer Adj OK",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "Any Peer Adj OK:",
		},
		{
			name: "JSON output contains admin_state",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"admin_state"`,
		},
		{
			name: "JSON output contains peers",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"peers"`,
		},
		{
			name: "JSON output contains local section",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"local"`,
		},
		{
			name: "JSON output local contains ha_state",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"ha_state"`,
		},
		{
			name: "JSON output local contains svc_state",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"svc_state"`,
		},
		{
			name: "JSON output local contains criteria_met",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"criteria_met"`,
		},
		{
			name: "JSON output local contains policy_check",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"policy_check"`,
		},
		{
			name: "JSON output local contains adjacency_reached",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"adjacency_reached"`,
		},
		{
			name: "JSON output contains any_peer_adj_ok",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"any_peer_adj_ok"`,
		},
		{
			name: "JSON output contains any_peer_mbr_fail",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"any_peer_mbr_fail"`,
		},
		{
			name: "JSON output contains any_peer_ha_ready",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"any_peer_ha_ready"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := createTestAgwWithNxosManager(t)
			result := agw.GnmiShowHa(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}

func TestGnmiShowDevice(t *testing.T) {
	cases := []struct {
		name           string
		msgData        ipc.MessageData
		expectContains string
	}{
		{
			name: "Text output",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "gNMI Device Store",
		},
		{
			name: "JSON output",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"serial_number"`,
		},
		{
			name: "JSON output contains connection status",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"connection_status"`,
		},
		{
			name: "JSON output contains controller endpoint",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"controller_endpoint"`,
		},
		{
			name: "JSON output contains controller port",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"controller_port"`,
		},
		{
			name: "JSON output contains controller version",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"controller_version"`,
		},
		{
			name: "JSON output contains system state",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"system_state"`,
		},
		{
			name: "JSON output contains reject reason",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"reject_reason"`,
		},
		{
			name: "JSON output contains skip reg",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"skip_reg"`,
		},
		{
			name: "JSON output contains skip reg reason",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"skip_reg_reason"`,
		},
		{
			name: "JSON output contains proxy_address",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"proxy_address"`,
		},
		{
			name: "JSON output contains system_state as string",
			msgData: ipc.MessageData{
				Flags: map[string]string{"json": "true"},
			},
			expectContains: `"system_state":"disabled"`,
		},
		{
			name: "Text output contains Proxy Address",
			msgData: ipc.MessageData{
				Flags: map[string]string{},
			},
			expectContains: "Proxy Address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := createTestAgwWithNxosManager(t)
			result := agw.GnmiShowDevice(context.Background(), tc.msgData)
			require.Contains(t, result, tc.expectContains)
		})
	}
}
