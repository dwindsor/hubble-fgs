package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDiffConfigSetsBySource(t *testing.T) {
	tests := []struct {
		name            string
		source          v1alpha.ConfigSource
		oldSet          map[v1alpha.ConfigType]*v1alpha.ConfigObject
		newSet          map[v1alpha.ConfigType]*v1alpha.ConfigObject
		expectedAdds    map[v1alpha.ConfigType]*v1alpha.ConfigObject
		expectedRemoves map[v1alpha.ConfigType]*v1alpha.ConfigObject
	}{
		{
			name:            "empty sets",
			source:          v1alpha.ConfigSource_CONFIG_SOURCE_UNSPECIFIED,
			oldSet:          map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			newSet:          map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "add config with matching source",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "add config with non-matching source - filtered out",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "remove config with matching source",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
			newSet:       map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
		},
		{
			name:   "remove config with non-matching source - filtered out",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
			newSet:          map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "mixed sources - only matching source included",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigLogIpfix{
						ConfigLogIpfix: &v1alpha.LogConfigIpfix{},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "modify config with matching source",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "modify config with non-matching source - filtered out",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
			},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "multiple configs with different sources - complex scenario",
			source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogIpfix{
						ConfigLogIpfix: &v1alpha.LogConfigIpfix{},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogTimescape{
						ConfigLogTimescape: &v1alpha.LogConfigTimescape{},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
				v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogTimescape{
						ConfigLogTimescape: &v1alpha.LogConfigTimescape{},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX: {
					Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX,
					Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP,
					Config: &v1alpha.ConfigObject_ConfigLogIpfix{
						ConfigLogIpfix: &v1alpha.LogConfigIpfix{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adds, removes := DiffConfigSetsBySource(tt.oldSet, tt.newSet, tt.source)

			// Check adds
			if len(adds) != len(tt.expectedAdds) {
				t.Errorf("Expected %d adds, got %d", len(tt.expectedAdds), len(adds))
			}
			for configType, expectedConfig := range tt.expectedAdds {
				actualConfig, exists := adds[configType]
				if !exists {
					t.Errorf("Expected add for config type %v not found", configType)
					continue
				}
				if !compareConfigObjects(actualConfig, expectedConfig) {
					t.Errorf("Added config for type %v does not match expected", configType)
				}
			}

			// Check removes
			if len(removes) != len(tt.expectedRemoves) {
				t.Errorf("Expected %d removes, got %d", len(tt.expectedRemoves), len(removes))
			}
			for configType, expectedConfig := range tt.expectedRemoves {
				actualConfig, exists := removes[configType]
				if !exists {
					t.Errorf("Expected remove for config type %v not found", configType)
					continue
				}
				if !compareConfigObjects(actualConfig, expectedConfig) {
					t.Errorf("Removed config for type %v does not match expected", configType)
				}
			}
		})
	}
}

func TestDiffConfigSets(t *testing.T) {
	tests := []struct {
		name            string
		oldSet          map[v1alpha.ConfigType]*v1alpha.ConfigObject
		newSet          map[v1alpha.ConfigType]*v1alpha.ConfigObject
		expectedAdds    map[v1alpha.ConfigType]*v1alpha.ConfigObject
		expectedRemoves map[v1alpha.ConfigType]*v1alpha.ConfigObject
	}{
		{
			name:            "empty sets",
			oldSet:          map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			newSet:          map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "nil old set",
			oldSet: nil,
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{
							ServiceIp: "192.168.1.1",
						},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{
							ServiceIp: "192.168.1.1",
						},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name:   "add new config",
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
					Config: &v1alpha.ConfigObject_ConfigLogSyslog{
						ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name: "modify existing config",
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
			},
			expectedAdds: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
					},
				},
			},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
		{
			name: "no changes",
			oldSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			newSet: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
					},
				},
			},
			expectedAdds:    map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
			expectedRemoves: map[v1alpha.ConfigType]*v1alpha.ConfigObject{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adds, removes := DiffConfigSets(tt.oldSet, tt.newSet)

			// Check adds
			if len(adds) != len(tt.expectedAdds) {
				t.Errorf("Expected %d adds, got %d", len(tt.expectedAdds), len(adds))
			}
			for configType, expectedConfig := range tt.expectedAdds {
				actualConfig, exists := adds[configType]
				if !exists {
					t.Errorf("Expected add for config type %v not found", configType)
					continue
				}
				if !compareConfigObjects(actualConfig, expectedConfig) {
					t.Errorf("Added config for type %v does not match expected", configType)
				}
			}

			// Check removes
			if len(removes) != len(tt.expectedRemoves) {
				t.Errorf("Expected %d removes, got %d", len(tt.expectedRemoves), len(removes))
			}
			for configType, expectedConfig := range tt.expectedRemoves {
				actualConfig, exists := removes[configType]
				if !exists {
					t.Errorf("Expected remove for config type %v not found", configType)
					continue
				}
				if !compareConfigObjects(actualConfig, expectedConfig) {
					t.Errorf("Removed config for type %v does not match expected", configType)
				}
			}
		})
	}
}

func TestCompareConfigObjects(t *testing.T) {
	tests := []struct {
		name     string
		a        *v1alpha.ConfigObject
		b        *v1alpha.ConfigObject
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name: "one nil",
			a:    nil,
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
			},
			expected: false,
		},
		{
			name: "different types",
			a: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
			},
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
			},
			expected: false,
		},
		{
			name: "identical DPU configs",
			a: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Config: &v1alpha.ConfigObject_ConfigDpu{
					ConfigDpu: &v1alpha.DpuConfig{
						ServiceIp: "192.168.1.1",
					},
				},
			},
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Config: &v1alpha.ConfigObject_ConfigDpu{
					ConfigDpu: &v1alpha.DpuConfig{
						ServiceIp: "192.168.1.1",
					},
				},
			},
			expected: true,
		},
		{
			name: "different DPU configs",
			a: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Config: &v1alpha.ConfigObject_ConfigDpu{
					ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.1"},
				},
			},
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Config: &v1alpha.ConfigObject_ConfigDpu{
					ConfigDpu: &v1alpha.DpuConfig{ServiceIp: "192.168.1.2"},
				},
			},
			expected: false,
		},
		{
			name: "identical syslog configs",
			a: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
				Config: &v1alpha.ConfigObject_ConfigLogSyslog{
					ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
				},
			},
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
				Config: &v1alpha.ConfigObject_ConfigLogSyslog{
					ConfigLogSyslog: &v1alpha.LogConfigSyslog{},
				},
			},
			expected: true,
		},
		{
			name: "unknown config type",
			a: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType(999),
			},
			b: &v1alpha.ConfigObject{
				Type: v1alpha.ConfigType(999),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareConfigObjects(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDiffLogConfigMaps(t *testing.T) {
	tests := []struct {
		name            string
		oldLogConfigs   map[string]*v1alpha.LogConfig
		newLogConfigs   map[string]*v1alpha.LogConfig
		expectedAdds    map[string]*v1alpha.LogConfig
		expectedRemoves map[string]*v1alpha.LogConfig
	}{
		{
			name:            "empty maps",
			oldLogConfigs:   map[string]*v1alpha.LogConfig{},
			newLogConfigs:   map[string]*v1alpha.LogConfig{},
			expectedAdds:    map[string]*v1alpha.LogConfig{},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name:          "nil old map",
			oldLogConfigs: nil,
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"new": {Id: "new"},
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"new": {Id: "new"},
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name: "nil new map",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"old": {Id: "old"},
			},
			newLogConfigs: nil,
			expectedAdds:  map[string]*v1alpha.LogConfig{},
			expectedRemoves: map[string]*v1alpha.LogConfig{
				"old": {Id: "old"},
			},
		},
		{
			name:          "add new config",
			oldLogConfigs: map[string]*v1alpha.LogConfig{},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"syslog1": {Id: "syslog1"},
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"syslog1": {Id: "syslog1"},
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name: "remove existing config",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"timescape1": {Id: "timescape1"},
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{},
			expectedAdds:  map[string]*v1alpha.LogConfig{},
			expectedRemoves: map[string]*v1alpha.LogConfig{
				"timescape1": {Id: "timescape1"},
			},
		},
		{
			name: "modify existing config",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"config1": {Id: "config1", Host: "old.example.com"},
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"config1": {Id: "config1", Host: "new.example.com"},
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"config1": {Id: "config1", Host: "new.example.com"},
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name: "no changes - identical configs",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"unchanged": {Id: "unchanged"},
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"unchanged": {Id: "unchanged"},
			},
			expectedAdds:    map[string]*v1alpha.LogConfig{},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name: "mixed operations - add, modify, remove, keep",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"keep":   {Id: "keep"},
				"modify": {Id: "modify", Host: "old.example.com"},
				"remove": {Id: "remove"},
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"keep":   {Id: "keep"},
				"modify": {Id: "modify", Host: "new.example.com"},
				"add":    {Id: "add"},
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"modify": {Id: "modify", Host: "new.example.com"},
				"add":    {Id: "add"},
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{
				"remove": {Id: "remove"},
			},
		},
		{
			name: "empty string keys",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"": {Id: ""},
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"": {Id: "", Host: "new-empty-key.example.com"},
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"": {Id: "", Host: "new-empty-key.example.com"},
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{},
		},
		{
			name: "nil config values",
			oldLogConfigs: map[string]*v1alpha.LogConfig{
				"nil-old": nil,
			},
			newLogConfigs: map[string]*v1alpha.LogConfig{
				"nil-new": nil,
			},
			expectedAdds: map[string]*v1alpha.LogConfig{
				"nil-new": nil,
			},
			expectedRemoves: map[string]*v1alpha.LogConfig{
				"nil-old": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adds, removes := DiffLogConfigMaps(tt.oldLogConfigs, tt.newLogConfigs)

			// Check adds
			if len(adds) != len(tt.expectedAdds) {
				t.Errorf("Expected %d adds, got %d", len(tt.expectedAdds), len(adds))
			}
			for key, expectedConfig := range tt.expectedAdds {
				actualConfig, exists := adds[key]
				if !exists {
					t.Errorf("Expected add for key '%s' not found", key)
					continue
				}
				if !cmp.Equal(expectedConfig, actualConfig, protocmp.Transform()) {
					t.Errorf("Added config for key '%s' does not match expected", key)
				}
			}

			// Check removes
			if len(removes) != len(tt.expectedRemoves) {
				t.Errorf("Expected %d removes, got %d", len(tt.expectedRemoves), len(removes))
			}
			for key, expectedConfig := range tt.expectedRemoves {
				actualConfig, exists := removes[key]
				if !exists {
					t.Errorf("Expected remove for key '%s' not found", key)
					continue
				}
				if !cmp.Equal(expectedConfig, actualConfig, protocmp.Transform()) {
					t.Errorf("Removed config for key '%s' does not match expected", key)
				}
			}
		})
	}
}
