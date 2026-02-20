// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"google.golang.org/protobuf/testing/protocmp"
)

// DiffConfigSetsBySource does the same as DiffConfigSets, but filters the map of config objects to add and remove by source.
// This can be used to only make changes to a specific source of config, like when updating config from a configmap.
func DiffConfigSetsBySource(oldSet map[v1alpha.ConfigType]*v1alpha.ConfigObject, newSet map[v1alpha.ConfigType]*v1alpha.ConfigObject, source v1alpha.ConfigSource) (configsToAdd map[v1alpha.ConfigType]*v1alpha.ConfigObject, configsToRemove map[v1alpha.ConfigType]*v1alpha.ConfigObject) {
	configsToAdd, configsToRemove = DiffConfigSets(oldSet, newSet)
	for configType, config := range configsToAdd {
		if config.Source != source {
			delete(configsToAdd, configType)
		}
	}
	for configType, config := range configsToRemove {
		if config.Source != source {
			delete(configsToRemove, configType)
		}
	}
	return configsToAdd, configsToRemove
}

// DiffConfigSets computes the difference between two config sets and returns the map of config objects to add and remove
// to the old set to match the new set. It compares the actual content of the objects, not just their existence.
func DiffConfigSets(oldSet map[v1alpha.ConfigType]*v1alpha.ConfigObject, newSet map[v1alpha.ConfigType]*v1alpha.ConfigObject) (configsToAdd map[v1alpha.ConfigType]*v1alpha.ConfigObject, configsToRemove map[v1alpha.ConfigType]*v1alpha.ConfigObject) {
	configsToAdd = make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)
	configsToRemove = make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)

	// Check for new or modified configs in newSet
	for configType, newConfig := range newSet {
		oldConfig, exists := oldSet[configType]
		if !exists || !compareConfigObjects(oldConfig, newConfig) {
			configsToAdd[configType] = newConfig
		}
	}

	// Check for configs that exist in oldSet but not in newSet
	for configType, oldConfig := range oldSet {
		_, exists := newSet[configType]
		if !exists {
			configsToRemove[configType] = oldConfig
		}
	}
	return configsToAdd, configsToRemove
}

// compareConfigObjects compares two config objects for equality
func compareConfigObjects(a, b *v1alpha.ConfigObject) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case v1alpha.ConfigType_CONFIG_TYPE_DPU:
		return cmp.Equal(a.GetConfigDpu(), b.GetConfigDpu(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
		return cmp.Equal(a.GetConfigLogSyslog(), b.GetConfigLogSyslog(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
		return cmp.Equal(a.GetConfigLogIpfix(), b.GetConfigLogIpfix(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
		return cmp.Equal(a.GetConfigLogTimescape(), b.GetConfigLogTimescape(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		return cmp.Equal(a.GetConfigLogSplunk(), b.GetConfigLogSplunk(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_HA:
		return cmp.Equal(a.GetConfigHa(), b.GetConfigHa(), protocmp.Transform())
	case v1alpha.ConfigType_CONFIG_TYPE_NETWORK:
		return cmp.Equal(a.GetNetworkConfig(), b.GetNetworkConfig(), protocmp.Transform())
	default:
		return false
	}
}

func DiffLogConfigMaps(oldLogConfigs, newLogConfigs map[string]*v1alpha.LogConfig) (logConfigAdds map[string]*v1alpha.LogConfig, logConfigRemoves map[string]*v1alpha.LogConfig) {
	logConfigAdds = make(map[string]*v1alpha.LogConfig)
	logConfigRemoves = make(map[string]*v1alpha.LogConfig)

	// Check for new or modified configs in newLogConfigs
	for key, newConfig := range newLogConfigs {
		oldConfig, exists := oldLogConfigs[key]
		if !exists || !cmp.Equal(oldConfig, newConfig, protocmp.Transform()) {
			logConfigAdds[key] = newConfig
		}
	}

	// Check for configs that exist in oldLogConfigs but not in newLogConfigs
	for key, oldConfig := range oldLogConfigs {
		_, exists := newLogConfigs[key]
		if !exists {
			logConfigRemoves[key] = oldConfig
		}
	}
	return logConfigAdds, logConfigRemoves
}

// IsNil checks if an interface is nil or points to nil
func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	vi := reflect.ValueOf(i)
	switch vi.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return vi.IsNil()
	}
	return false
}
