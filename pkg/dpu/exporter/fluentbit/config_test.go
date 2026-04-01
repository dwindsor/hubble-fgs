// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fluentbit

import (
	"reflect"
	"strings"
	"testing"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func TestAddLogConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	originalSSHDir := FLB_SSH_DIR
	FLB_SSH_DIR = tempDir
	defer func() {
		FLB_SSH_DIR = originalSSHDir
	}()

	tests := []struct {
		name           string
		fbc            FluentBitConfig
		typ            v1alpha.ConfigType
		logCfg         *v1alpha.LogConfig
		wantErr        bool
		errContains    string
		expectedOutput *OutputSection
		outputCount    int
	}{
		{
			name: "add syslog config without TLS",
			fbc:  DefaultBaseConfig(),
			typ:  v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			logCfg: &v1alpha.LogConfig{
				Id:       "test-syslog",
				Host:     "192.168.1.100",
				Port:     "514",
				Protocol: "udp",
				Tls:      false,
			},
			wantErr:     false,
			outputCount: 1,
			expectedOutput: &OutputSection{
				Name:  "syslog",
				Alias: "test-syslog",
				Match: "*",
				Properties: map[string]string{
					"host":                "192.168.1.100",
					"port":                "514",
					"mode":                "udp",
					"syslog_format":       "rfc5424",
					"syslog_severity_key": "severity_code",
					"syslog_facility_key": "facility",
					"syslog_hostname_key": "hostname",
					"syslog_appname_key":  "appname",
					"syslog_procid_key":   "pid",
					"syslog_msgid_key":    "msg_code",
					"syslog_sd_key":       "extradata",
					"syslog_message_key":  "message",
				},
			},
		},
		{
			name: "add syslog config with TLS",
			fbc:  DefaultBaseConfig(),
			typ:  v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			logCfg: &v1alpha.LogConfig{
				Id:       "test-syslog-tls",
				Host:     "secure.example.com",
				Port:     "6514",
				Protocol: "tcp",
				Tls:      true,
				Auth: &v1alpha.LogConfig_BasicAuth{
					BasicAuth: &v1alpha.BasicAuth{
						Username: "testuser",
						Password: "testpass",
					},
				},
			},
			wantErr:     false,
			outputCount: 1,
			// Note: TLS properties will be validated in separate TLS test
		},
		{
			name: "add timescape config",
			fbc:  DefaultBaseConfig(),
			typ:  v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE,
			logCfg: &v1alpha.LogConfig{
				Id:   "test-timescape",
				Host: "timescape.example.com",
				Port: "4260",
				Tls:  false,
			},
			wantErr:     false,
			outputCount: 1,
			expectedOutput: &OutputSection{
				Name:  "http",
				Alias: "test-timescape",
				Match: "*",
				Properties: map[string]string{
					"host":   "timescape.example.com",
					"port":   "4260",
					"uri":    "/push",
					"format": "json",
				},
			},
		},
		{
			name:        "unsupported config type - ipfix",
			fbc:         DefaultBaseConfig(),
			typ:         v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX,
			logCfg:      &v1alpha.LogConfig{Id: "test-ipfix"},
			wantErr:     true,
			errContains: "ipfix fluentbit support not implemented",
		},
		{
			name:        "unsupported config type - splunk",
			fbc:         DefaultBaseConfig(),
			typ:         v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK,
			logCfg:      &v1alpha.LogConfig{Id: "test-splunk"},
			wantErr:     true,
			errContains: "splunk fluentbit support not implemented",
		},
		{
			name:        "unsupported config type - unknown",
			fbc:         DefaultBaseConfig(),
			typ:         v1alpha.ConfigType_CONFIG_TYPE_DPU,
			logCfg:      &v1alpha.LogConfig{Id: "test-unknown"},
			wantErr:     true,
			errContains: "fluentbit support not implemented for config type",
		},
		{
			name:    "nil log config",
			fbc:     DefaultBaseConfig(),
			typ:     v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			logCfg:  nil,
			wantErr: true,
		},
		{
			name: "empty log config values",
			fbc:  DefaultBaseConfig(),
			typ:  v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			logCfg: &v1alpha.LogConfig{
				Id:       "",
				Host:     "",
				Port:     "",
				Protocol: "",
			},
			wantErr:     false,
			outputCount: 1,
			expectedOutput: &OutputSection{
				Name:  "syslog",
				Alias: "",
				Match: "*",
				Properties: map[string]string{
					"host":                "",
					"port":                "",
					"mode":                "",
					"syslog_format":       "rfc5424",
					"syslog_severity_key": "severity_code",
					"syslog_facility_key": "facility",
					"syslog_hostname_key": "hostname",
					"syslog_appname_key":  "appname",
					"syslog_procid_key":   "pid",
					"syslog_msgid_key":    "msg_code",
					"syslog_sd_key":       "extradata",
					"syslog_message_key":  "message",
				},
			},
		},
		{
			name: "add to existing config with outputs",
			fbc: FluentBitConfig{
				Pipeline: PipelineSection{
					Outputs: []OutputSection{
						{
							Name:  "existing",
							Alias: "existing-output",
							Match: "existing.*",
						},
					},
				},
			},
			typ: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			logCfg: &v1alpha.LogConfig{
				Id:       "new-output",
				Host:     "new.example.com",
				Port:     "514",
				Protocol: "tcp",
			},
			wantErr:     false,
			outputCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle nil logCfg case specially to avoid panic
			if tt.logCfg == nil {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic for nil logCfg, but didn't panic")
					}
				}()
			}

			result, err := AddLogConfig(tt.fbc, tt.typ, tt.logCfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Check output count
			if tt.outputCount > 0 && len(result.Pipeline.Outputs) != tt.outputCount {
				t.Errorf("Expected %d outputs, got %d", tt.outputCount, len(result.Pipeline.Outputs))
				return
			}

			// Check expected output if provided
			if tt.expectedOutput != nil {
				if len(result.Pipeline.Outputs) == 0 {
					t.Errorf("Expected output but got none")
					return
				}

				// Find the output we just added (should be the last one)
				actualOutput := result.Pipeline.Outputs[len(result.Pipeline.Outputs)-1]

				if actualOutput.Name != tt.expectedOutput.Name {
					t.Errorf("Expected output name '%s', got '%s'", tt.expectedOutput.Name, actualOutput.Name)
				}
				if actualOutput.Alias != tt.expectedOutput.Alias {
					t.Errorf("Expected output alias '%s', got '%s'", tt.expectedOutput.Alias, actualOutput.Alias)
				}
				if actualOutput.Match != tt.expectedOutput.Match {
					t.Errorf("Expected output match '%s', got '%s'", tt.expectedOutput.Match, actualOutput.Match)
				}

				// Check properties
				for key, expectedValue := range tt.expectedOutput.Properties {
					if actualValue, exists := actualOutput.Properties[key]; !exists {
						t.Errorf("Expected property '%s' not found", key)
					} else if actualValue != expectedValue {
						t.Errorf("Expected property '%s' = '%s', got '%s'", key, expectedValue, actualValue)
					}
				}
			}
		})
	}
}

func TestRemoveLogConfig(t *testing.T) {
	tests := []struct {
		name            string
		fbc             FluentBitConfig
		id              string
		expectedOutputs []OutputSection
	}{
		{
			name: "remove existing config",
			fbc: FluentBitConfig{
				Pipeline: PipelineSection{
					Outputs: []OutputSection{
						{
							Name:  "syslog",
							Alias: "config-1",
							Match: "*",
							Properties: map[string]string{
								"host": "example.com",
								"port": "514",
							},
						},
						{
							Name:  "http",
							Alias: "config-2",
							Match: "*",
							Properties: map[string]string{
								"host": "timescape.com",
								"port": "4260",
							},
						},
					},
				},
			},
			id: "config-1",
			expectedOutputs: []OutputSection{
				{
					Name:  "http",
					Alias: "config-2",
					Match: "*",
					Properties: map[string]string{
						"host": "timescape.com",
						"port": "4260",
					},
				},
			},
		},
		{
			name: "remove non-existent config",
			fbc: FluentBitConfig{
				Pipeline: PipelineSection{
					Outputs: []OutputSection{
						{
							Name:  "syslog",
							Alias: "config-1",
							Match: "*",
						},
					},
				},
			},
			id: "non-existent",
			expectedOutputs: []OutputSection{
				{
					Name:  "syslog",
					Alias: "config-1",
					Match: "*",
				},
			},
		},
		{
			name:            "remove from empty config",
			fbc:             FluentBitConfig{},
			id:              "any-id",
			expectedOutputs: []OutputSection{},
		},
		{
			name: "remove all configs with same alias",
			fbc: FluentBitConfig{
				Pipeline: PipelineSection{
					Outputs: []OutputSection{
						{
							Name:  "syslog",
							Alias: "duplicate-id",
							Match: "*",
						},
						{
							Name:  "http",
							Alias: "duplicate-id",
							Match: "*",
						},
						{
							Name:  "stdout",
							Alias: "different-id",
							Match: "*",
						},
					},
				},
			},
			id: "duplicate-id",
			expectedOutputs: []OutputSection{
				{
					Name:  "stdout",
					Alias: "different-id",
					Match: "*",
				},
			},
		},
		{
			name: "remove with empty id",
			fbc: FluentBitConfig{
				Pipeline: PipelineSection{
					Outputs: []OutputSection{
						{
							Name:  "syslog",
							Alias: "",
							Match: "*",
						},
						{
							Name:  "http",
							Alias: "config-1",
							Match: "*",
						},
					},
				},
			},
			id: "",
			expectedOutputs: []OutputSection{
				{
					Name:  "http",
					Alias: "config-1",
					Match: "*",
				},
			},
		},
		{
			name: "remove preserves other pipeline sections",
			fbc: FluentBitConfig{
				Service: ServiceSection{
					Flush:    "1",
					LogLevel: "info",
				},
				Pipeline: PipelineSection{
					Inputs: []InputSection{
						{
							Name: "syslog",
							Tag:  "input-tag",
						},
					},
					Filters: []FilterSection{
						{
							Name:  "grep",
							Match: "*",
						},
					},
					Outputs: []OutputSection{
						{
							Name:  "syslog",
							Alias: "to-remove",
							Match: "*",
						},
					},
				},
				Parsers: []ParserSection{
					{
						Name:   "json",
						Format: "json",
					},
				},
			},
			id:              "to-remove",
			expectedOutputs: []OutputSection{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveLogConfig(tt.fbc, tt.id)

			// Check expected outputs
			if len(result.Pipeline.Outputs) != len(tt.expectedOutputs) {
				t.Errorf("Expected %d outputs, got %d", len(tt.expectedOutputs), len(result.Pipeline.Outputs))
				return
			}

			for i, expectedOutput := range tt.expectedOutputs {
				if i >= len(result.Pipeline.Outputs) {
					t.Errorf("Expected output at index %d not found", i)
					continue
				}

				actualOutput := result.Pipeline.Outputs[i]
				if actualOutput.Name != expectedOutput.Name {
					t.Errorf("Output %d: expected name '%s', got '%s'", i, expectedOutput.Name, actualOutput.Name)
				}
				if actualOutput.Alias != expectedOutput.Alias {
					t.Errorf("Output %d: expected alias '%s', got '%s'", i, expectedOutput.Alias, actualOutput.Alias)
				}
				if actualOutput.Match != expectedOutput.Match {
					t.Errorf("Output %d: expected match '%s', got '%s'", i, expectedOutput.Match, actualOutput.Match)
				}

				// Check properties if they exist
				if expectedOutput.Properties != nil {
					for key, expectedValue := range expectedOutput.Properties {
						if actualValue, exists := actualOutput.Properties[key]; !exists {
							t.Errorf("Output %d: expected property '%s' not found", i, key)
						} else if actualValue != expectedValue {
							t.Errorf("Output %d: expected property '%s' = '%s', got '%s'", i, key, expectedValue, actualValue)
						}
					}
				}
			}
		})
	}
}

// TestAddLogConfigMTLSCertManager tests that mTLS configuration with cert-manager is handled correctly
func TestAddLogConfigMTLSCertManager(t *testing.T) {
	logCfg := &v1alpha.LogConfig{
		Id:   "mtls-test",
		Host: "secure.example.com",
		Port: "6514",
		Tls:  true,
		Auth: &v1alpha.LogConfig_Mtls{
			Mtls: &v1alpha.MTLSConfig{
				Enabled: true,
				Certmanager: &v1alpha.MTLSCertManager{
					IssuerRef: &v1alpha.IssuerRef{
						Group: "cert-manager.io",
						Kind:  "ClusterIssuer",
						Name:  "test-issuer",
					},
				},
			},
		},
	}

	fbc := DefaultBaseConfig()
	result, err := AddLogConfig(fbc, v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, logCfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check that TLS is enabled
	output := result.Pipeline.Outputs[0]
	if output.Properties["tls"] != "On" {
		t.Errorf("Expected tls to be 'On', got %s", output.Properties["tls"])
	}

	// With cert-manager, certificate files are not created by this function
	// They will be managed by cert-manager and mounted via Kubernetes secrets

	// Verify basic output properties
	if output.Name != "syslog" {
		t.Errorf("Expected output name to be 'syslog', got %s", output.Name)
	}
	if output.Alias != "mtls-test" {
		t.Errorf("Expected output alias to be 'mtls-test', got %s", output.Alias)
	}
}

// TestConfigImmutability tests that the original config is not modified
func TestConfigImmutability(t *testing.T) {
	originalFBC := FluentBitConfig{
		Service: ServiceSection{
			Flush: "original",
		},
		Pipeline: PipelineSection{
			Outputs: []OutputSection{
				{
					Name:  "original",
					Alias: "original-alias",
				},
			},
		},
	}

	// Make a deep copy for comparison
	expectedFBC := FluentBitConfig{
		Service: ServiceSection{
			Flush: "original",
		},
		Pipeline: PipelineSection{
			Outputs: []OutputSection{
				{
					Name:  "original",
					Alias: "original-alias",
				},
			},
		},
	}

	logCfg := &v1alpha.LogConfig{
		Id:   "new-config",
		Host: "example.com",
		Port: "514",
	}

	// Test AddLogConfig doesn't modify original
	_, err := AddLogConfig(originalFBC, v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, logCfg)
	if err != nil {
		t.Fatalf("AddLogConfig failed: %v", err)
	}

	if !reflect.DeepEqual(originalFBC, expectedFBC) {
		t.Errorf("AddLogConfig modified the original config")
	}

	// Test RemoveLogConfig doesn't modify original
	_ = RemoveLogConfig(originalFBC, "original-alias")

	if !reflect.DeepEqual(originalFBC, expectedFBC) {
		t.Errorf("RemoveLogConfig modified the original config")
	}
}
