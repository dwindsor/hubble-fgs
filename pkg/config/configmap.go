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

func AddConfigMapInformer(ctx context.Context, m *manager.ControllerManager) error {
	// This watches all ConfigMaps, not just the specific smartswitch
	// TODO: Narrow down this watcher to only get updates on smartswitch configmap
	informer, err := m.Manager.GetCache().GetInformer(ctx, &v1.ConfigMap{})
	if err != nil {
		return err
	}
	_, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addConfigMap(obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateConfigMap(oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				deleteConfigMap(obj)
			}})
	return err
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
	configsToAdd, configsToRemove := DiffConfigSets(library.GetRepository().GetConfigObjects(), configObjMap)
	for _, obj := range configsToAdd {
		library.GetRepository().AddConfig(obj)
	}
	for _, obj := range configsToRemove {
		library.GetRepository().DeleteConfig(obj.Type)
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
		configObj := &v1alpha.ConfigObject{}
		switch cType {
		case "dpu":
			configObj.Type = v1alpha.ConfigType_CONFIG_TYPE_DPU
			var dpuCfg v1alpha.DpuConfig
			err := json.Unmarshal([]byte(jsonData), &dpuCfg)
			if err != nil {
				logger.GetLogger().Error("Failed to parse DPU config", "type", cType, "json", jsonData)
				continue
			}
			configObj.Config = &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &dpuCfg}
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
