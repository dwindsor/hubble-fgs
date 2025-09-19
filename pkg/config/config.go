package config

import (
	"reflect"

	"github.com/gogo/protobuf/proto"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

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
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case v1alpha.ConfigType_CONFIG_TYPE_DPU:
		return proto.Equal(a.GetConfigDpu(), b.GetConfigDpu())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
		return proto.Equal(a.GetConfigLogSyslog(), b.GetConfigLogSyslog())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
		return proto.Equal(a.GetConfigLogIpfix(), b.GetConfigLogIpfix())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
		return proto.Equal(a.GetConfigLogTimescape(), b.GetConfigLogTimescape())
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		return proto.Equal(a.GetConfigLogSplunk(), b.GetConfigLogSplunk())
	default:
		return false
	}
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
