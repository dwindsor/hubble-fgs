// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager"
	"k8s.io/client-go/tools/cache"

	"github.com/isovalent/hubble-fgs/pkg/model/switchevents/policystatus"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

type AGWMetricsInterface interface {
	RecordDPUInsertError()
	RecordDPUUpdateError()
	RecordDPUDeleteError()
}

type smartSwitchNetworkPolicyWatcher struct {
	policyHandler       PolicyHandler
	policyStatusHandler policystatus.PolicyStatusHandler
	metricsCollector    MetricsCollectorInterface
}

type MetricsCollectorInterface interface {
	GetAGWMetrics() AGWMetricsInterface
	SetPolicyHandler(PolicyHandler)
}

// SetPolicyStatusHandler sets the policy status handler for failure reporting
func (w *smartSwitchNetworkPolicyWatcher) SetPolicyStatusHandler(handler policystatus.PolicyStatusHandler) {
	w.policyStatusHandler = handler
}

// SetMetricsCollector sets the metrics collector
func (w *smartSwitchNetworkPolicyWatcher) SetMetricsCollector(collector MetricsCollectorInterface) {
	w.metricsCollector = collector
}

func (w *smartSwitchNetworkPolicyWatcher) addSmartSwitchNetworkPolicy(ctx context.Context, obj any) {
	switch np := obj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		resourceID := NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)
		policies, err := ToSmartSwitchNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("addNetworkPolicy: failed to convert SmartSwitchNetworkPolicy to SmartSwitch network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)

			if w.metricsCollector != nil {
				w.metricsCollector.GetAGWMetrics().RecordDPUInsertError()
			}

			// Report conversion failure to timescape
			w.reportPolicyValidationStatus(ctx, "add-conversion", np, resourceID.String(), err)
			return
		}
		var k8sRulesList K8sRulesList
		for _, pol := range policies {
			hash, err := pol.Hash()
			if err != nil {
				logger.GetLogger().Error("failed to calculate policy checksum, corrupted policy rule", logfields.Error, err, "title", resourceID, "policy rule", *pol)

				if w.metricsCollector != nil {
					w.metricsCollector.GetAGWMetrics().RecordDPUInsertError()
				}
				// Report hash calculation failure to timescape
				w.reportPolicyValidationStatus(ctx, "add-hash", np, resourceID.String(), err)
				continue
			}
			k8sRulesList = append(k8sRulesList, NewPolicyRule(hex.EncodeToString(hash[:]), pol))
		}

		err = w.policyHandler.UpsertPolicy(resourceID, k8sRulesList, np.ResourceVersion)
		if err != nil {
			logger.GetLogger().Warn("addNetworkPolicy: aborted", logfields.Error, err, "title", resourceID, "network rules", int64(len(k8sRulesList)), "resource version", np.ResourceVersion)

			// Record DPU insert error
			if w.metricsCollector != nil {
				w.metricsCollector.GetAGWMetrics().RecordDPUInsertError()
			}

			// Report upsert failure to timescape
			w.reportPolicyValidationStatus(ctx, "add-upsert", np, resourceID.String(), err)
			return
		}

		logger.GetLogger().Info("addNetworkPolicy: completed successfully", "title", resourceID, "network rules", int64(len(k8sRulesList)), "resource version", np.ResourceVersion)

	default:
		logger.GetLogger().Warn("addNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
	}
}

func (w *smartSwitchNetworkPolicyWatcher) updateSmartSwitchNetworkPolicy(ctx context.Context, oldObj, newObj any) {
	switch np := newObj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		if np.DeletionTimestamp != nil {
			logger.GetLogger().Debug("updateNetworkPolicy: skipping update for policy being deleted", "network-policy-name", np.Name)
			return
		}
		if oldNp, ok := oldObj.(*isovalentv1.SmartSwitchNetworkPolicy); ok && oldNp.Generation == np.Generation {
			logger.GetLogger().Debug("updateNetworkPolicy: skipping metadata-only update", "network-policy-name", np.Name)
			return
		}
		resourceID := NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)
		policies, err := ToSmartSwitchNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("updateNetworkPolicy: failed to convert SmartSwitchNetworkPolicy to SmartSwitch network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)

			// Record DPU update error
			if w.metricsCollector != nil {
				w.metricsCollector.GetAGWMetrics().RecordDPUUpdateError()
			}

			// Report conversion failure to timescape
			w.reportPolicyValidationStatus(ctx, "update-conversion", np, resourceID.String(), err)
			return
		}
		var k8sRulesList K8sRulesList
		for _, pol := range policies {
			hash, err := pol.Hash()
			if err != nil {
				logger.GetLogger().Error("failed to calculate policy checksum, corrupted policy rule", logfields.Error, err, "title", resourceID, "policy rule", *pol)

				// Record DPU update error
				if w.metricsCollector != nil {
					w.metricsCollector.GetAGWMetrics().RecordDPUUpdateError()
				}
				// Report hash calculation failure to timescape
				w.reportPolicyValidationStatus(ctx, "update-hash", np, resourceID.String(), err)
				continue
			}
			k8sRulesList = append(k8sRulesList, NewPolicyRule(hex.EncodeToString(hash[:]), pol))
		}
		err = w.policyHandler.UpsertPolicy(resourceID, k8sRulesList, np.ResourceVersion)
		if err != nil {
			logger.GetLogger().Warn("updateNetworkPolicy: aborted", logfields.Error, err, "title", resourceID, "network rules", int64(len(k8sRulesList)), "resource version", np.ResourceVersion)

			// Record DPU update error
			if w.metricsCollector != nil {
				w.metricsCollector.GetAGWMetrics().RecordDPUUpdateError()
			}

			// Report upsert failure to timescape
			w.reportPolicyValidationStatus(ctx, "update-upsert", np, resourceID.String(), err)
			return
		}
		logger.GetLogger().Info("updateNetworkPolicy: completed successfully", "title", resourceID, "network rules", int64(len(k8sRulesList)), "resource version", np.ResourceVersion)

	default:
		logger.GetLogger().Warn("updateNetworkPolicy: invalid type", "obj", newObj, "obj-type", fmt.Sprintf("%T", newObj))
	}
}

func (w *smartSwitchNetworkPolicyWatcher) deleteSmartSwitchNetworkPolicy(ctx context.Context, obj any) {
	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	switch np := obj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		resourceID := NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)

		err := w.policyHandler.DeletePolicy(resourceID, np.ResourceVersion)
		if err != nil {
			logger.GetLogger().Warn("SmartSwitchNetworkPolicy deletion failed", logfields.Error, err, "title", resourceID, "resource version", np.ResourceVersion)

			// Record DPU delete error
			if w.metricsCollector != nil {
				w.metricsCollector.GetAGWMetrics().RecordDPUDeleteError()
			}

			// Report deletion failure to timescape
			w.reportPolicyValidationStatus(ctx, "delete", np, resourceID.String(), err)
			return
		}

		logger.GetLogger().Info("SmartSwitchNetworkPolicy successfully deleted", "title", resourceID, "resource version", np.ResourceVersion)

	default:
		logger.GetLogger().Warn("deleteNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
	}
}

func AddSmartSwitchNetworkPolicyInformer(ctx context.Context, m *manager.ControllerManager, policyHandler PolicyHandler, policyStatusHandler policystatus.PolicyStatusHandler, metricsCollector MetricsCollectorInterface) error {
	informer, err := m.Manager.GetCache().GetInformer(ctx, &isovalentv1.SmartSwitchNetworkPolicy{})
	if err != nil {
		return err
	}

	watcher := smartSwitchNetworkPolicyWatcher{
		policyHandler: policyHandler,
		// report policy status during agw policy validation failure or success
		policyStatusHandler: policyStatusHandler,
		// Add metrics collector
		metricsCollector: metricsCollector,
	}
	// Set policy handler in metrics collector for real-time metrics
	if watcher.metricsCollector != nil {
		watcher.metricsCollector.SetPolicyHandler(policyHandler)
	}

	_, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				watcher.addSmartSwitchNetworkPolicy(ctx, obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				watcher.updateSmartSwitchNetworkPolicy(ctx, oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				watcher.deleteSmartSwitchNetworkPolicy(ctx, obj)
			}})
	return err
}

func isStagingPolicy(np *isovalentv1.SmartSwitchNetworkPolicy) bool {
	if ann := np.GetAnnotations(); ann != nil {
		_, found := ann[AnnotationStaging]
		return found
	}
	return false
}

// reportPolicyFailure reports policy operation failure to timescape
func (w *smartSwitchNetworkPolicyWatcher) reportPolicyValidationStatus(ctx context.Context, operation string, np *isovalentv1.SmartSwitchNetworkPolicy, policyName string, err error) {
	if w.policyStatusHandler == nil {
		if err != nil {
			logger.GetLogger().Warn("Policy status handler not set, cannot report policy status to timescape", "operation", operation, "policyName", np.Name, "namespace", np.Namespace, "resourceVersion", np.ResourceVersion, "error", err)
		}
		return
	}

	namespace := np.Namespace
	resourceVersion := np.ResourceVersion

	// Use operation type as rule name for failure reporting
	ruleName := fmt.Sprintf("%s-status", operation)

	// Report the failure asynchronously to avoid blocking policy processing
	go func() {
		reportCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		reportErr := w.policyStatusHandler.ReportPolicyValidationStatus(reportCtx, policyName, namespace, ruleName, resourceVersion, err)

		statusType := "success"
		if err != nil {
			statusType = "failure"
		}
		if reportErr != nil {

			logger.GetLogger().Warn("failed to report policy operation status to timescape",
				"operation", operation,
				"statusType", statusType,
				"policyName", policyName,
				"resourceVersion", resourceVersion,
				"originalError", err,
				"reportError", reportErr)
		} else {
			logger.GetLogger().Debug("successfully reported policy operation status to timescape",
				"operation", operation,
				"statusType", statusType,
				"policyName", policyName,
				"resourceVersion", resourceVersion)
		}

	}()
}
