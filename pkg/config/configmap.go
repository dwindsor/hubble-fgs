// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package config

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
)

type IConnectionMonitor interface {
	StartMonitoring(ctx context.Context)
	CreateEventHandlers(ctx context.Context) cache.ResourceEventHandlerFuncs
}

// configMapCache stores all processed ConfigMaps to maintain complete state
var configMapCache = make(map[string]*v1.ConfigMap)

func AddConfigMapInformer(ctx context.Context, m *manager.ControllerManager, configmapNames []string, connMonitor IConnectionMonitor) error {
	// This watches all ConfigMaps, not just the specific smartswitch
	// TODO: Narrow down this watcher to only get updates on smartswitch configmap
	informer, err := m.Manager.GetCache().GetInformer(ctx, &v1.ConfigMap{})
	if err != nil {
		logger.GetLogger().Error("Failed to create ConfigMap informer", "error", err)
		return err
	}

	// Get event handlers from the connection monitor that handle both ConfigMap processing and connection monitoring
	var eventHandlers cache.ResourceEventHandlerFuncs
	if connMonitor != nil {
		eventHandlers = connMonitor.CreateEventHandlers(ctx)
	}

	// Decorator pattern:
	// The following wraps the event handlers from the connection monitor so that
	// ConfigMap processing (add, update, delete) always occurs before the connection
	// monitoring logic is invoked.
	wrappedHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			// Process ConfigMap first for all watched ConfigMaps
			for _, configmapName := range configmapNames {
				addConfigMap(obj, configmapName)
			}
			// Then call connection monitor
			if eventHandlers.AddFunc != nil {
				eventHandlers.AddFunc(obj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			// Process ConfigMap first for all watched ConfigMaps
			for _, configmapName := range configmapNames {
				updateConfigMap(oldObj, newObj, configmapName)
			}
			// Then call connection monitor
			if eventHandlers.UpdateFunc != nil {
				eventHandlers.UpdateFunc(oldObj, newObj)
			}
		},
		DeleteFunc: func(obj any) {
			// Process ConfigMap first for all watched ConfigMaps
			for _, configmapName := range configmapNames {
				deleteConfigMap(obj, configmapName)
			}
			// Then call connection monitor
			if eventHandlers.DeleteFunc != nil {
				eventHandlers.DeleteFunc(obj)
			}
		},
	}

	_, err = informer.AddEventHandler(wrappedHandlers)
	if err != nil {
		logger.GetLogger().Error("Failed to add event handler to ConfigMap informer", "error", err)
		return err
	}

	// Start connection monitoring
	if connMonitor != nil {
		connMonitor.StartMonitoring(ctx)
		logger.GetLogger().Info("Connection monitoring with ConfigMap informer started")
	}

	return nil
}

func addConfigMap(obj any, name string) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != name {
		return
	}

	logger.GetLogger().Info("ConfigMap added", "name", cm.Name, "namespace", cm.Namespace)

	// Update the cache with the new ConfigMap
	configMapCache[cm.Name] = cm

	// Parse ALL ConfigMaps to get complete config state for proper reconciliation
	configObjMap := ParseAllConfigMaps()
	configsToAdd, configsToRemove := DiffConfigSetsBySource(library.GetRepository().GetConfigObjects(), configObjMap, v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP)
	for _, obj := range configsToRemove {
		library.GetRepository().DeleteConfig(obj.Type)
	}
	for _, obj := range configsToAdd {
		library.GetRepository().AddConfig(obj)
	}
}

func updateConfigMap(oldObj any, newObj any, name string) {
	oldCm, ok := oldObj.(*v1.ConfigMap)
	if !ok {
		logger.GetLogger().Debug("updateConfigMap: oldObj is not ConfigMap", "type", fmt.Sprintf("%T", oldObj))
		return
	}
	newCm, ok := newObj.(*v1.ConfigMap)
	if !ok {
		logger.GetLogger().Debug("updateConfigMap: newObj is not ConfigMap", "type", fmt.Sprintf("%T", newObj))
		return
	}
	if oldCm.Name != name || newCm.Name != name || oldCm.Name != newCm.Name {
		return
	}

	logger.GetLogger().Info("ConfigMap updated", "name", newCm.Name, "namespace", newCm.Namespace)

	// Update the cache with the new ConfigMap
	configMapCache[newCm.Name] = newCm

	// Parse ALL ConfigMaps to get complete config state, not just the changed one
	configObjMap := ParseAllConfigMaps()
	configsToAdd, configsToRemove := DiffConfigSetsBySource(library.GetRepository().GetConfigObjects(), configObjMap, v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP)
	for _, obj := range configsToRemove {
		library.GetRepository().DeleteConfig(obj.Type)
	}
	for _, obj := range configsToAdd {
		library.GetRepository().AddConfig(obj)
	}
}

func deleteConfigMap(obj any, name string) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != name {
		return
	}

	logger.GetLogger().Info("ConfigMap deleted", "name", cm.Name, "namespace", cm.Namespace)

	// Remove from cache
	delete(configMapCache, cm.Name)

	// Parse ALL remaining ConfigMaps to get updated config state
	configObjMap := ParseAllConfigMaps()
	configsToAdd, configsToRemove := DiffConfigSetsBySource(library.GetRepository().GetConfigObjects(), configObjMap, v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP)
	for _, obj := range configsToRemove {
		library.GetRepository().DeleteConfig(obj.Type)
	}
	for _, obj := range configsToAdd {
		library.GetRepository().AddConfig(obj)
	}
}

func ParseConfigMap(cm *v1.ConfigMap) map[v1alpha.ConfigType]*v1alpha.ConfigObject {
	configObjMap := map[v1alpha.ConfigType]*v1alpha.ConfigObject{}

	// Iterate through all key-value pairs in the ConfigMap
	for cType, jsonData := range cm.Data {
		logger.GetLogger().Debug("Processing ConfigMap key", "key", cType, "configMapName", cm.Name)
		configObj := &v1alpha.ConfigObject{Source: v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP}
		switch cType {
		case "log_syslog":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG
			var syslogCfg v1alpha.LogConfigSyslog
			err := json.Unmarshal([]byte(jsonData), &syslogCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse Syslog config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigLogSyslog{ConfigLogSyslog: &syslogCfg}
		case "flow_export_ipfix":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_FLOW_EXPORT_IPFIX
			var ipfixCfg v1alpha.FlowExportConfigIpfix
			err := json.Unmarshal([]byte(jsonData), &ipfixCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse IPFIX config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigFlowExportIpfix{ConfigFlowExportIpfix: &ipfixCfg}
		case "log_timescape":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE
			var timescapeCfg v1alpha.LogConfigTimescape
			err := json.Unmarshal([]byte(jsonData), &timescapeCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse Timescape config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigLogTimescape{ConfigLogTimescape: &timescapeCfg}
		case "log_splunk":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK
			var splunkCfg v1alpha.LogConfigSplunk
			err := json.Unmarshal([]byte(jsonData), &splunkCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse Splunk config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigLogSplunk{ConfigLogSplunk: &splunkCfg}
		case "timescape_config":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_TIMESCAPE
			var timescapeConfig v1alpha.TimescapeConfig
			err := json.Unmarshal([]byte(jsonData), &timescapeConfig)
			if err != nil {
				logger.GetLogger().Error("Failed to parse Timescape config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigTimescape{ConfigTimescape: &timescapeConfig}
		default:
			logger.GetLogger().Error("Unknown config type", "type", cType)
			continue
		}

		// Add the config object to the map
		configObjMap[configObj.Type] = configObj
		logger.GetLogger().Debug("Parsed config object", "type", configObj.Type, "config", configObj)
	}

	return configObjMap
}

// ParseAllConfigMaps retrieves complete configuration state from cached ConfigMaps
func ParseAllConfigMaps() map[v1alpha.ConfigType]*v1alpha.ConfigObject {
	configObjMap := make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)

	// Parse all cached ConfigMaps and merge results
	for _, cm := range configMapCache {
		cmConfigs := ParseConfigMap(cm)
		for configType, configObj := range cmConfigs {
			configObjMap[configType] = configObj
		}
	}

	return configObjMap
}
