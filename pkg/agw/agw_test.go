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
					Host: "127.0.0.1",
					Port: "514",
					Mode: "tcp",
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
					Host: "192.168.1.1",
					Port: "1514",
					Mode: "udp",
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
					Host: "not-an-ip",
					Port: "514",
					Mode: "tcp",
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
					Host: "127.0.0.1",
					Port: "abc",
					Mode: "tcp",
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
					Host: "127.0.0.1",
					Port: "70000",
					Mode: "tcp",
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
					Host: "127.0.0.1",
					Port: "514",
					Mode: "foo",
				},
			},
			errMsg: "invalid mode: must be 'tcp' or 'udp'",
		},
		{
			name: "Empty type",
			cfg: LogConfigData{
				Id:   "id7",
				Type: "",
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "tcp",
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
					Host: "",
					Port: "514",
					Mode: "tcp",
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
					Host: "127.0.0.1",
					Port: "",
					Mode: "tcp",
				},
			},
			errMsg: "invalid port: must be a valid integer",
		},
		{
			name: "Empty mode",
			cfg: LogConfigData{
				Id:   "id10",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "",
				},
			},
			errMsg: "log mode is required",
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
						"mode": "tcp"
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
						"mode": "udp"
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
						"mode": "tcp"
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
						"mode": "tcp"
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
						"mode": "tcp"
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
						"mode": "tcp"
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
						"mode": "tcp"
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
						"mode": "foo"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid mode: must be 'tcp' or 'udp'",
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
	agw := &AgentGateway{}
	// Load a valid syslog config
	input := `{
		"sys1": {
			"id": "sys1",
			"type": "syslog",
			"config": {
				"host": "127.0.0.1",
				"port": "514",
				"mode": "tcp"
			},
			"secrets": {
				"token": "tok",
				"username": "user",
				"password": "pass",
				"ca": "ca",
				"cert": "cert",
				"key": "key",
				"key_password": "keypass"
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
	require.Contains(t, out, `"username": "user"`)
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
				"mode": "tcp"
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
