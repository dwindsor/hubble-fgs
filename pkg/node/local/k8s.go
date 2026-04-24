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

package local

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/isovalent/hubble-fgs/pkg/manager"
)

type KubernetesMetadataService struct {
	node *corev1.Node
}

func (m *KubernetesMetadataService) GetHostname(_ context.Context) (string, error) {
	return m.node.GetName(), nil
}

func (m *KubernetesMetadataService) GetInstanceId(_ context.Context) (string, error) {
	return m.node.GetName(), nil
}

func (m *KubernetesMetadataService) GetInternalIP(_ context.Context) (string, error) {
	for _, addr := range m.node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address, nil
		}
	}
	return "", nil
}

func (m *KubernetesMetadataService) GetExternalIP(_ context.Context) (string, error) {
	for _, addr := range m.node.Status.Addresses {
		if addr.Type == corev1.NodeExternalIP {
			return addr.Address, nil
		}
	}
	return "", nil
}

func (m *KubernetesMetadataService) GetInternalDNS(_ context.Context) (string, error) {
	for _, addr := range m.node.Status.Addresses {
		if addr.Type == corev1.NodeInternalDNS {
			return addr.Address, nil
		}
	}
	return "", nil
}

func (m *KubernetesMetadataService) GetExternalDNS(_ context.Context) (string, error) {
	for _, addr := range m.node.Status.Addresses {
		if addr.Type == corev1.NodeExternalDNS {
			return addr.Address, nil
		}
	}
	return "", nil
}

func (m *KubernetesMetadataService) GetKubernetesNode(_ context.Context) (*corev1.Node, error) {
	return m.node, nil
}

func NewKubernetesMetadataService(manager manager.KubernetesManager) (*KubernetesMetadataService, error) {
	node, err := manager.GetControllerManager().GetNode()
	if err != nil {
		return nil, err
	}

	return &KubernetesMetadataService{node: node}, nil
}

func (m *KubernetesMetadataService) GetLabels(_ context.Context) (map[string]string, error) {
	return m.node.GetLabels(), nil
}
