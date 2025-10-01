package netpol

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

func addTetragonNetworkPolicy(obj any) {
	var policies []*types.TetragonNetworkPolicy
	var crd *v1alpha1.TetragonNetworkPolicy
	var crdNS *v1alpha1.TetragonNetworkPolicyNamespaced
	var err error

	name := ""

	if !option.Config.EnableTCP {
		logger.GetLogger().Warn("addNetworkPolicy: network policies require --" + option.KeyEnableTCP)
	}

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		name = np.Name
		crd = np
		policies, err = ToTetragonNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("addNetworkPolicy: failed to convert TetragonNetworkPolicy to Tetragon network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)
			return
		}

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().Warn("addNetworkPolicy: namespaced policy currently not supported",
			"obj", obj,
			"obj-type", fmt.Sprintf("%T", obj))
		return

	default:
		logger.GetLogger().Warn("addNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	err = loadPolicy(&library.PolicyStory{
		Title:       name,
		CRDPolicy:   crd,
		CRDNSPolicy: crdNS,
		IrPolicy:    policies,
	})

	if err != nil {
		logger.GetLogger().Warn("addNetworkPolicy: aborted", logfields.Error, err, "title", name, "network rules", len(policies), "network policy", policies)
		return
	}

	logger.GetLogger().Info("addNetworkPolicy: completed successfully", "title", name, "network rules", len(policies), "network policy", policies)
}

func getCurrentNameAndAltName(resourceName string) (string, bool, string) {
	altName := "__" + resourceName
	policy := library.GetRepository().Get(resourceName)
	if policy != nil {
		return resourceName, true, altName
	}

	policy = library.GetRepository().Get(altName)
	if policy != nil {
		return altName, true, resourceName
	}

	return resourceName, false, altName
}

func updateTetragonNetworkPolicy(_, newObj any) {
	var newPolicy []*types.TetragonNetworkPolicy
	var crd *v1alpha1.TetragonNetworkPolicy
	var crdNS *v1alpha1.TetragonNetworkPolicyNamespaced
	var err error

	resourceName := ""

	switch np := newObj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		resourceName = np.Name
		crd = np
		newPolicy, err = ToTetragonNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().Warn("updateNetworkPolicy: failed to convert TetragonNetworkPolicy to Tetragon network policy", logfields.Error, err,
				"network-policy-name", np.Name,
				"network-policy-namespace", np.Namespace)
			return
		}

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().Warn("updateNetworkPolicy: namespaced policy currently not supported", "obj", newObj,
			"obj-type", fmt.Sprintf("%T", newObj))
		return

	default:
		logger.GetLogger().Warn("updateNetworkPolicy: invalid type", "obj", newObj,
			"obj-type", fmt.Sprintf("%T", newObj))
		return
	}

	oldName, ok, newName := getCurrentNameAndAltName(resourceName)
	if !ok {
		logger.GetLogger().Debug("updateNetworkPolicy: update but policy does not exist",
			"new title", newName,
			"old title", oldName,
			"network rules", len(newPolicy))
	}

	// Policy update is slightly complicated to avoid having a gap
	// in policy. First we create the updated policy and only then
	// do we remove the previous policy.
	library.GetRepository().Add(&library.PolicyStory{
		Title:       newName,
		CRDPolicy:   crd,
		CRDNSPolicy: crdNS,
		IrPolicy:    newPolicy,
	})
	err = dns.CreateMatchLabelsPolicySet(newPolicy)
	if err != nil {
		logger.GetLogger().Warn("updateNetworkPolicy: failed to create new state in an update to Tetragon network policy command",
			"new title", newName, "old title", oldName, "network rules", len(newPolicy))
	}

	if err := deleteNetworkPolicy(oldName); err != nil {
		logger.GetLogger().Warn("updateNetworkPolicy: failed to remove old state in an update to Tetragon network policy command",
			logfields.Error, err, "new name", newName, "old name", oldName)
	}

	logger.GetLogger().Info("updateNetworkPolicy: completed successfully",
		"title", newName, "oldTitle", oldName, "new network rules", len(newPolicy))
}

func deleteNetworkPolicyObj(obj any) {
	resourceName := ""

	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		resourceName = np.Name

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().Warn("deleteNetworkPolicy: namespaced policy currently not supported", "obj", obj,
			"obj-type", fmt.Sprintf("%T", obj))

	default:
		logger.GetLogger().Warn("deleteNetworkPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	currentName, ok, _ := getCurrentNameAndAltName(resourceName)
	if !ok {
		logger.GetLogger().Warn("TetragonNetworkPolicy deletion failed, policy does not exist", "name", resourceName)
		return
	}

	err := deleteNetworkPolicy(currentName)
	if err != nil {
		logger.GetLogger().Warn("TetragonNetworkPolicy deletion failed", logfields.Error, err)
	}
	logger.GetLogger().Info("TetragonNetworkPolicy successfully deleted", "name", resourceName)

}

func deleteNetworkPolicy(name string) error {
	story := library.GetRepository().Get(name)
	if story == nil {
		return fmt.Errorf("policy %q does not exist", name)
	}
	if err := dns.RemoveNetworkPolicySet(story.IrPolicy); err != nil {
		return fmt.Errorf("removing policy %q failed: %w", name, err)
	}
	library.GetRepository().Delete(name)
	return nil
}

func AddTetragonNetworkPolicyInformer(ctx context.Context, m *manager.ControllerManager) error {
	informer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.TetragonNetworkPolicy{})
	if err != nil {
		return err
	}
	_, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addTetragonNetworkPolicy(obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateTetragonNetworkPolicy(oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				deleteNetworkPolicyObj(obj)
			}})
	return err
}

func loadPolicy(policyStory *library.PolicyStory) error {
	if library.GetRepository().Get(policyStory.Title) != nil {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.Title)
	}

	existTest := fmt.Sprintf("__%s", policyStory.Title)
	if library.GetRepository().Get(existTest) != nil {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.Title)
	}

	library.GetRepository().Add(policyStory)

	err := dns.CreateMatchLabelsPolicySet(policyStory.IrPolicy)
	if err != nil {
		return fmt.Errorf("failed create match label from policy set %s: %w", policyStory.Title, err)
	}
	return nil
}
