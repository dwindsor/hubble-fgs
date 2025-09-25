package config

import (
	"testing"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	v1 "k8s.io/api/core/v1"
)

func TestParseConfigMap(t *testing.T) {
	tests := []struct {
		Name         string
		ConfigMap    *v1.ConfigMap
		ConfigObjMap map[v1alpha.ConfigType]*v1alpha.ConfigObject
	}{
		{
			Name:         "empty configmap",
			ConfigMap:    &v1.ConfigMap{},
			ConfigObjMap: make(map[v1alpha.ConfigType]*v1alpha.ConfigObject),
		},
		{
			Name: "single value configmap (empty config)",
			ConfigMap: &v1.ConfigMap{
				Data: map[string]string{
					"dpu": `{}`,
				},
			},
			ConfigObjMap: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{},
					},
				},
			},
		},
		{
			Name: "single value configmap (invalid config)",
			ConfigMap: &v1.ConfigMap{
				Data: map[string]string{
					"invalid": `{}`,
				},
			},
			ConfigObjMap: make(map[v1alpha.ConfigType]*v1alpha.ConfigObject),
		},
		{
			Name: "single value configmap",
			ConfigMap: &v1.ConfigMap{
				Data: map[string]string{
					"dpu": `{
						"service_ip": "1.1.1.1",
						"service_mac": "00:1a:2b:3c:4d:5e",
						"port_low": 7000,
						"port_high": 8000
					}`,
				},
			},
			ConfigObjMap: map[v1alpha.ConfigType]*v1alpha.ConfigObject{
				v1alpha.ConfigType_CONFIG_TYPE_DPU: {
					Type: v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{
						ConfigDpu: &v1alpha.DpuConfig{
							ServiceIp:  "1.1.1.1",
							ServiceMac: "00:1a:2b:3c:4d:5e",
							PortLow:    7000,
							PortHigh:   8000,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result := ParseConfigMap(tt.ConfigMap)
			for cType, configObj := range result {
				expectedConfigObj, exists := tt.ConfigObjMap[cType]
				if !exists {
					t.Errorf("config object for type %s not found in ConfigObjMap", cType)
					continue
				}
				if !compareConfigObjects(configObj, expectedConfigObj) {
					t.Errorf("config object for type %s does not match the expected object", cType)
				}
			}
		})
	}
}
