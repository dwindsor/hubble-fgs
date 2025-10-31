// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package node

import (
	"context"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

// Register defines the interface for registering a TetragonNode.
type Register interface {
	Register(ctx context.Context) error
}

// NewNodeRegisterer returns a Register implementation based on the current
// environment. If running in AWS with K8s control plane enabled, it returns a
// registerer that uses the provided metadata service to register the node.
// Otherwise, it returns a no-op registerer.
func NewNodeRegisterer(metadata local.MetadataService) (Register, error) {
	if option.Config.Environment == option.EnvironmentAWS && option.K8SControlPlaneEnabled() {
		return &registerer{
			metadata: metadata,
			client:   manager.Get().GetControllerManager().Manager.GetClient(),
		}, nil
	}
	return &noOpsRegisterer{}, nil
}

type noOpsRegisterer struct{}

func (n *noOpsRegisterer) Register(_ context.Context) error {
	return nil
}

type registerer struct {
	metadata local.MetadataService
	client   client.Client
}

func (r *registerer) Register(ctx context.Context) error {
	desired, err := desiredNode(ctx, r.metadata)
	if err != nil {
		return err
	}
	temp := desired.DeepCopy()
	res, err := controllerutil.CreateOrPatch(ctx, r.client, temp, nil)
	if err != nil {
		return err
	}
	if res != controllerutil.OperationResultUpdatedStatus {
		temp.Status = desired.Status
		if err = r.client.Status().Update(ctx, temp); err != nil {
			return err
		}
	}
	return nil
}

func desiredNode(ctx context.Context, metadata local.MetadataService) (*v1alpha1.TetragonNode, error) {
	name, err := metadata.GetHostname(ctx)
	if err != nil {
		return nil, err
	}
	labels, err := metadata.GetLabels(ctx)
	if err != nil {
		return nil, err
	}
	validLables, invalidLabels := sanitizeLabels(labels)
	if len(invalidLabels) > 0 {
		logger.GetLogger().Warn("Skip these invalid labels were invalid in k8s TetragonNode resource",
			"invalidLabels", invalidLabels)
	}
	id, err := metadata.GetInstanceId(ctx)
	if err != nil {
		return nil, err
	}

	var addresses []v1alpha1.NodeAddress
	for _, pair := range []struct {
		t  v1alpha1.AddressType
		fn func(context.Context) (string, error)
	}{
		{t: v1alpha1.NodeHostName, fn: metadata.GetHostname},
		{t: v1alpha1.NodeInternalIP, fn: metadata.GetInternalIP},
		{t: v1alpha1.NodeExternalIP, fn: metadata.GetExternalIP},
		{t: v1alpha1.NodeInternalDNS, fn: metadata.GetInternalDNS},
		{t: v1alpha1.NodeExternalDNS, fn: metadata.GetExternalDNS},
	} {
		address, err := pair.fn(ctx)
		if err == nil && len(address) > 0 {
			addresses = append(addresses, v1alpha1.NodeAddress{
				Type: pair.t,
				IP:   address,
			})
		}
	}

	return &v1alpha1.TetragonNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    validLables,
		},
		Status: v1alpha1.TetragonNodeStatus{
			Id:              id,
			Addresses:       addresses,
			SoftwareVersion: version.Version,
			Conditions: []metav1.Condition{
				{
					Type:               "NodeRegistered",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.Now(),
					Reason:             "NodeRegistered",
					Message:            "Node successfully registered",
				},
			},
		},
	}, nil
}

func sanitizeLabels(labels map[string]string) (map[string]string, map[string]string) {
	sanitized := make(map[string]string)
	invalid := make(map[string]string)
	for k, v := range labels {
		labelNameErrors := validation.IsQualifiedName(k)
		labelValueErrors := validation.IsValidLabelValue(v)
		if len(labelNameErrors) > 0 || len(labelValueErrors) > 0 {
			logger.GetLogger().Warn("Ignored invalid label for TetragonNode",
				"label", k, "value", v,
				"nameErrors", labelNameErrors,
				"valueErrors", labelValueErrors)
			invalid[k] = v
			continue
		}
		sanitized[k] = v
	}
	return sanitized, invalid
}
