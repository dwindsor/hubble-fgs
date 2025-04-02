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

	dns.CreateMatchLabelsPolicySet(policy)

	logger.GetLogger().WithFields(logrus.Fields{
		"title":         name,
		"policy":        policy,
		"network rules": len(policy),
	}).Info("adding network policy")

	policyLibrary[name] = policyStory{
		title:       name,
		crdPolicy:   crd,
		crdNSPolicy: crdNS,
		irPolicy:    policy,
	}
}

func updateTetragonNetworkPolicy(old, n any) {
	logger.GetLogger().WithFields(logrus.Fields{
		"oldObj": old,
		"newObj": n,
	}).Debug("updateTetragonNetworkPolicy not supported")
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

	story := policyLibrary[name]
	if err := dns.RemoveNetworkPolicySet(name, story.irPolicy); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": name,
		}).WithError(err).Warn("remove from policyLibrary failed")
	}
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
