package agw

import (
	"context"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/token"

	"github.com/stretchr/testify/require"
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
			expected: "token123",
		},
		{
			name: "Multiple tokens",
			setup: func(agw *AgentGateway) {
				agw.Token = token.GetAgentToken()
				agw.Token.SetK8sAuthToken("tokenA,tokenB")
			},
			expected: "tokenA,tokenB",
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

// --- Test for PingFwa ---

func TestPingFwa(t *testing.T) {
	agw := &AgentGateway{}
	result := agw.PingFwa(context.Background(), "dpu1")
	if result != "" {
		require.Equal(t, "", result)
	}
}
