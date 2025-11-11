package config

import (
	"context"
	"encoding/json"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
)

const (
	CONFIGMAP_NAME = "smartswitch-config"
)

type IConnectionMonitor interface {
	StartMonitoring(ctx context.Context)
	CreateEventHandlers(ctx context.Context) cache.ResourceEventHandlerFuncs
}

func AddConfigMapInformer(ctx context.Context, m *manager.ControllerManager, connMonitor IConnectionMonitor) error {
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
			// Process ConfigMap first
			addConfigMap(obj)
			// Then call connection monitor
			if eventHandlers.AddFunc != nil {
				eventHandlers.AddFunc(obj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			// Process ConfigMap first
			updateConfigMap(oldObj, newObj)
			// Then call connection monitor
			if eventHandlers.UpdateFunc != nil {
				eventHandlers.UpdateFunc(oldObj, newObj)
			}
		},
		DeleteFunc: func(obj any) {
			// Process ConfigMap first
			deleteConfigMap(obj)
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

func addConfigMap(obj any) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != CONFIGMAP_NAME {
		return
	}

	logger.GetLogger().Info("ConfigMap added", "name", cm.Name, "namespace", cm.Namespace)

	// Parse configmap values and add them to config store
	configObjMap := ParseConfigMap(cm)
	for _, obj := range configObjMap {
		err := library.GetRepository().AddConfig(obj)
		if err != nil {
			logger.GetLogger().Error("Failed to parse configmap into config object", "type", obj.Type, "json", obj.Config)
		}
	}
}

func updateConfigMap(oldObj any, newObj any) {
	oldCm, ok := oldObj.(*v1.ConfigMap)
	if !ok {
		return
	}
	newCm, ok := newObj.(*v1.ConfigMap)
	if !ok {
		return
	}
	if oldCm.Name != CONFIGMAP_NAME || newCm.Name != CONFIGMAP_NAME || oldCm.Name != newCm.Name {
		return
	}

	logger.GetLogger().Info("ConfigMap updated", "name", newCm.Name, "namespace", newCm.Namespace)

	// Parse configmap values and reconcile them with the current config library
	configObjMap := ParseConfigMap(newCm)
	configsToAdd, configsToRemove := DiffConfigSetsBySource(library.GetRepository().GetConfigObjects(), configObjMap, v1alpha.ConfigSource_CONFIG_SOURCE_CONFIGMAP)
	for _, obj := range configsToRemove {
		library.GetRepository().DeleteConfig(obj.Type)
	}
	for _, obj := range configsToAdd {
		library.GetRepository().AddConfig(obj)
	}
}

func deleteConfigMap(obj any) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok {
		return
	}
	if cm.Name != CONFIGMAP_NAME {
		return
	}

	logger.GetLogger().Info("ConfigMap deleted", "name", cm.Name, "namespace", cm.Namespace)

	// Parse configmap values and remove them from config store
	configObjMap := ParseConfigMap(cm)
	for _, obj := range configObjMap {
		library.GetRepository().DeleteConfig(obj.Type)
	}
}

func ParseConfigMap(cm *v1.ConfigMap) map[v1alpha.ConfigType]*v1alpha.ConfigObject {
	configObjMap := map[v1alpha.ConfigType]*v1alpha.ConfigObject{}

	// Iterate through all key-value pairs in the ConfigMap
	for cType, jsonData := range cm.Data {
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
		case "log_ipfix":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX
			var ipfixCfg v1alpha.LogConfigIpfix
			err := json.Unmarshal([]byte(jsonData), &ipfixCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse IPFIX config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigLogIpfix{ConfigLogIpfix: &ipfixCfg}
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
		default:
			logger.GetLogger().Error("Unknown config type", "type", cType)
			continue
		}

		// Add the config object to the map
		configObjMap[configObj.Type] = configObj
		logger.GetLogger().Info("Parsed config object", "type", configObj.Type, "config", configObj)
	}

	return configObjMap
}
