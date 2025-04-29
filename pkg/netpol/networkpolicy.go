package netpol

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/option"
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
	var policies []*types.TetragonNetworkPolicy
	var crd *v1alpha1.TetragonNetworkPolicy
	var crdNS *v1alpha1.TetragonNetworkPolicyNamespaced
	var err error

	name := ""

	if !option.Config.EnableTCP {
		logger.GetLogger().Warnf("addNetworkPolicy: network policies require --%s", option.KeyEnableTCP)
	}

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		name = np.Name
		crd = np
		policies, err = ToTetragonNetworkPolicies(np)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"network-policy-name":      np.ObjectMeta.Name,
				"network-policy-namespace": np.ObjectMeta.Namespace,
			}).WithError(err).Warn("addNetworkPolicy: failed to convert TetragonNetworkPolicy to Tetragon network policy")
			return
		}

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addNetworkPolicy: namespaced policy currently not supported")
		return

	default:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addNetworkPolicy: invalid type")
		return
	}

	err = loadPolicy(policyStory{
		title:       name,
		crdPolicy:   crd,
		crdNSPolicy: crdNS,
		irPolicy:    policies,
	})

	if err != nil {
		logger.GetLogger().WithError(err).WithFields(logrus.Fields{
			"title":         name,
			"policy":        policies,
			"network rules": len(policies),
		}).Warn("addNetworkPolicy: aborted")
		return
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"title":         name,
		"policy":        policies,
		"network rules": len(policies),
	}).Info("addNetworkPolicy: completed successfully")
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
		newName = np.Name
		crd = np
		newPolicy, err = ToTetragonNetworkPolicies(np)
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
		}).Warn("updateNetworkPolicy: namespaced policy currently not supported")
		return

	default:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      newObj,
			"obj-type": fmt.Sprintf("%T", newObj),
		}).Warn("updateNetworkPolicy: invalid type")
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
			}).Debug("updateNetworkPolicy: update but policy does not exist")
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
		}).Warn("updateNetworkPolicy: failed to create new state in an update to Tetragon network policy command")
	}

	if err := dns.RemoveNetworkPolicySet(oldName, oldStory.irPolicy); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"new name": newName,
			"old name": oldName,
		}).WithError(err).Warn("updateNetworkPolicy: failed to remove old state in an update to Tetragon network policy command")
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
	}).Info("updateNetworkPolicy: completed successfully")
}

func deleteNetworkPolicy(obj any) {
	name := ""

	switch np := obj.(type) {
	case *v1alpha1.TetragonNetworkPolicy:
		name = np.Name

	case *v1alpha1.TetragonNetworkPolicyNamespaced:
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("deleteNetworkPolicy: namespaced policy currently not supported")

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
			}).Warn("deleteNetworkPolicy: abort policy does not exist")
			return
		}
		name = deleteName
	}
	if err := dns.RemoveNetworkPolicySet(name, story.irPolicy); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": name,
		}).WithError(err).Warn("deleteNetworkPolicy: abort removing policy failed")
		return
	}
	delete(policyLibrary, name)

	logger.GetLogger().WithFields(logrus.Fields{
		"title": name,
	}).Info("deleteNetworkPolicy: completed successfully")
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
				deleteNetworkPolicy(obj)
			}})
	return err
}

func init() {
	policyLibrary = make(map[string]policyStory)
}

func loadPolicy(policyStory policyStory) error {
	_, exist := policyLibrary[policyStory.title]
	if exist {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.title)
	}

	existTest := fmt.Sprintf("__%s", policyStory.title)
	_, exist = policyLibrary[existTest]
	if exist {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.title)
	}

	err := dns.CreateMatchLabelsPolicySet(policyStory.irPolicy)
	if err != nil {
		return fmt.Errorf("failed create match label from policy set %s: %w", policyStory.title, err)
	}
	policyLibrary[policyStory.title] = policyStory

	return nil
}
