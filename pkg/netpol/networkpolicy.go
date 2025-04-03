package netpol

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

type policyStory struct {
	title       string
	crdPolicy   *v1alpha1.TetragonNetworkPolicy
	crdNSPolicy *v1alpha1.TetragonNetworkPolicyNamespaced
	irPolicy    []*types.TetragonNetworkPolicy
}

var policyLibrary map[string]policyStory

func addTetragonNetworkPolicy(obj any) {
	var policy []*types.TetragonNetworkPolicy
	var crd *v1alpha1.TetragonNetworkPolicy
	var crdNS *v1alpha1.TetragonNetworkPolicyNamespaced
	var err error

	name := ""

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		name = np.ObjectMeta.Name
		crd = np
		policy, err = ToTetragonNetworkPolicy(np)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"network-policy-name": np.ObjectMeta.Name,
			}).WithError(err).Warn("AddNetworkPolicy: failed to convert to Tetragon network policy")
			return
		}

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		name = np.ObjectMeta.Name
		crdNS = np
		policy, err = ToTetragonNetworkPolicyNamespaced(np)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"network-policy-name":      np.ObjectMeta.Name,
				"network-policy-namespace": np.ObjectMeta.Namespace,
			}).WithError(err).Warn("AddNetworkPolicy: failed to convert to Tetragon network policy")
			return
		}

	default:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addNetworkPolicy: invalid type")
		return
	}

	_, ok := policyLibrary[name]
	if ok {
		logger.GetLogger().WithFields(logrus.Fields{
			"title":         name,
			"policy":        policy,
			"network rules": len(policy),
		}).Warn("Policy create overwriting existing network policy")
		return
	}

	existTest := fmt.Sprintf("__%s", name)
	_, ok = policyLibrary[existTest]
	if ok {
		logger.GetLogger().WithFields(logrus.Fields{
			"title":         name,
			"policy":        policy,
			"network rules": len(policy),
		}).Warn("Policy create overwriting existing network policy")
		return
	}

	dns.CreateMatchLabelsPolicySet(policy)
	policyLibrary[name] = policyStory{
		title:       name,
		crdPolicy:   crd,
		crdNSPolicy: crdNS,
		irPolicy:    policy,
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"title":         name,
		"policy":        policy,
		"network rules": len(policy),
	}).Info("adding network policy")
}

func updateTetragonNetworkPolicy(_, newObj any) {
	var newPolicy []*types.TetragonNetworkPolicy
	var crd *v1alpha1.TetragonNetworkPolicy
	var crdNS *v1alpha1.TetragonNetworkPolicyNamespaced
	var err error

	newName := ""
	oldName := ""

	switch np := newObj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		newName = np.ObjectMeta.Name
		crd = np
		newPolicy, err = ToTetragonNetworkPolicy(np)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"network-policy-name":      np.ObjectMeta.Name,
				"network-policy-namespace": np.ObjectMeta.Namespace,
			}).WithError(err).Warn("updateNetworkPolicy: failed to convert TetragonNetworkPolicy to Tetragon network policy")
			return
		}

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      newObj,
			"obj-type": fmt.Sprintf("%T", newObj),
		}).Warn("updateNetworkPolicy: not supported")
		return

	default:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      newObj,
			"obj-type": fmt.Sprintf("%T", newObj),
		}).Warn("deleteNetworkPolicy: invalid type")
		return
	}

	oldName = fmt.Sprintf("__%s", newName)
	oldStory, ok := policyLibrary[oldName]
	if !ok {
		t := newName
		newName = oldName
		oldName = t

		oldStory, ok = policyLibrary[oldName]
		if !ok {
			logger.GetLogger().WithFields(logrus.Fields{
				"new title":     newName,
				"old title":     oldName,
				"network rules": len(newPolicy),
			}).Warn("Policy update but policy does not exist")
		}
	}

	// rename policy to secondary name so we can have both old and
	// new policy in the datapath simultaneously with unique names.
	// names are used to generate UIDs so we must do this or naming
	// collisions will happen.
	for _, p := range newPolicy {
		p.Name = newName
	}

	// Policy update is slightly complicated to avoid having a gap
	// in policy. First we create the updated policy and only then
	// do we remove the previous policy.
	err = dns.CreateMatchLabelsPolicySet(newPolicy)
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"new title":     newName,
			"old title":     oldName,
			"network rules": len(newPolicy),
		}).Warn("failed to create new state in an update Tetragon network policy command")
	}

	if err := dns.RemoveNetworkPolicySet(oldName, oldStory.irPolicy); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"new name": newName,
			"old name": oldName,
		}).WithError(err).Warn("failed to remove old state in an update Tetragon network policy command")
	}

	delete(policyLibrary, oldName)
	policyLibrary[newName] = policyStory{
		title:       newName,
		crdPolicy:   crd,
		crdNSPolicy: crdNS,
		irPolicy:    newPolicy,
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"title":             newName,
		"oldTitle":          oldName,
		"new network rules": len(newPolicy),
	}).Info("updated network policy")
}

func deleteNetworkPolicy(obj any) {
	name := ""

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		name = np.ObjectMeta.Name

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		name = np.ObjectMeta.Name

	default:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("deleteNetworkPolicy: invalid type")
		return
	}

	story, ok := policyLibrary[name]
	if !ok {
		deleteName := fmt.Sprintf("__%s", name)
		story, ok = policyLibrary[deleteName]
		if !ok {
			logger.GetLogger().WithFields(logrus.Fields{
				"name": name,
			}).Warn("deleteNetworkPolicy does not exist")
			return // nothing to delete
		}
		name = deleteName
	}
	if err := dns.RemoveNetworkPolicySet(name, story.irPolicy); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": name,
		}).WithError(err).Warn("remove from policyLibrary failed")
	}
	delete(policyLibrary, name)

	logger.GetLogger().WithFields(logrus.Fields{
		"title": name,
	}).Info("deleted network policy")
}

func AddTetragonNetworkPolicyInformer(_ context.Context, w watcher.Watcher) error {
	if w == nil {
		return fmt.Errorf("k8s watcher not initialized")
	}
	factory := w.GetCRDInformerFactory()
	if factory == nil {
		return fmt.Errorf("CRD informer factory not initialized")
	}

	informer := factory.Cilium().V1alpha1().TetragonNetworkPolicies().Informer()
	informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addTetragonNetworkPolicy(obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateTetragonNetworkPolicy(oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				deleteNetworkPolicy(obj)
			}})
	err := w.AddInformer("TetragonNetworkPolicy", informer, nil)
	if err != nil {
		return fmt.Errorf("failed to add TetragonNetworkPolicy informer: %w", err)
	}

	return nil
}

func init() {
	policyLibrary = make(map[string]policyStory)
}
