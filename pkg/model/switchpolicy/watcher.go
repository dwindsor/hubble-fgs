package switchpolicy

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager"
	"k8s.io/client-go/tools/cache"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

type smartSwitchNetworkPolicyWatcher struct {
	policyHandler PolicyHandler
}

func (w *smartSwitchNetworkPolicyWatcher) addSmartSwitchNetworkPolicy(obj any) {
	var policies []*SmartSwitchNetworkPolicy
	var err error
	var resourceID ResourceID

	switch np := obj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		resourceID = NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)
		policies, err = ToSmartSwitchNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("addNetworkPolicy: failed to convert SmartSwitchNetworkPolicy to SmartSwitch network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)
			return
		}

	default:
		logger.GetLogger().Warn("addNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	var k8sRulesList K8sRulesList
	for _, pol := range policies {
		hash, err := pol.Hash()
		if err != nil {
			logger.GetLogger().Error("failed to calculate policy checksum, corrupted policy rule", logfields.Error, err, "title", resourceID, "policy rule", *pol)
			continue
		}
		k8sRulesList = append(k8sRulesList, NewPolicyRule(hex.EncodeToString(hash[:]), pol))
	}
	err = w.policyHandler.UpsertPolicy(resourceID, k8sRulesList)
	if err != nil {
		logger.GetLogger().Warn("addNetworkPolicy: aborted", logfields.Error, err, "title", resourceID, "network rules", len(policies), "network policy", policies)
		return
	}

	logger.GetLogger().Info("addNetworkPolicy: completed successfully", "title", resourceID, "network rules", len(policies), "network policy", policies)
}

func (w *smartSwitchNetworkPolicyWatcher) updateSmartSwitchNetworkPolicy(_, newObj any) {
	var policies []*SmartSwitchNetworkPolicy
	var err error
	var resourceID ResourceID

	switch np := newObj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		resourceID = NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)
		policies, err = ToSmartSwitchNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("updateNetworkPolicy: failed to convert SmartSwitchNetworkPolicy to SmartSwitch network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)
			return
		}

	default:
		logger.GetLogger().Warn("updateNetworkPolicy: invalid type", "obj", newObj,
			"obj-type", fmt.Sprintf("%T", newObj))
		return
	}

	var k8sRulesList K8sRulesList
	for _, pol := range policies {
		hash, err := pol.Hash()
		if err != nil {
			logger.GetLogger().Error("failed to calculate policy checksum, corrupted policy rule", logfields.Error, err, "title", resourceID, "policy rule", *pol)
			continue
		}
		k8sRulesList = append(k8sRulesList, NewPolicyRule(hex.EncodeToString(hash[:]), pol))
	}
	err = w.policyHandler.UpsertPolicy(resourceID, k8sRulesList)
	if err != nil {
		logger.GetLogger().Warn("updateNetworkPolicy: aborted", logfields.Error, err, "title", resourceID, "network rules", len(policies), "network policy", policies)
		return
	}

	logger.GetLogger().Info("updateNetworkPolicy: completed successfully", "title", resourceID, "network rules", len(policies), "network policy", policies)
}

func (w *smartSwitchNetworkPolicyWatcher) deleteSmartSwitchNetworkPolicy(obj any) {
	var err error
	var resourceID ResourceID

	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	switch np := obj.(type) {
	case *isovalentv1.SmartSwitchNetworkPolicy:
		if isStagingPolicy(np) {
			return
		}
		resourceID = NewResourceID(isovalentv1.SNPKindDefinition, np.Namespace, np.Name)

	default:
		logger.GetLogger().Warn("deleteNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	err = w.policyHandler.DeletePolicy(resourceID)
	if err != nil {
		logger.GetLogger().Warn("SmartSwitchNetworkPolicy deletion failed", logfields.Error, err, "title", resourceID)
		return
	}
	logger.GetLogger().Info("SmartSwitchNetworkPolicy successfully deleted", "title", resourceID)
}

func AddSmartSwitchNetworkPolicyInformer(ctx context.Context, m *manager.ControllerManager, policyHandler PolicyHandler) error {
	informer, err := m.Manager.GetCache().GetInformer(ctx, &isovalentv1.SmartSwitchNetworkPolicy{})
	if err != nil {
		return err
	}
	watcher := smartSwitchNetworkPolicyWatcher{policyHandler: policyHandler}
	_, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				watcher.addSmartSwitchNetworkPolicy(obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				watcher.updateSmartSwitchNetworkPolicy(oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				watcher.deleteSmartSwitchNetworkPolicy(obj)
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
