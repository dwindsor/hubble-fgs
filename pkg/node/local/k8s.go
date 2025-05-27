// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package local

import (
	"github.com/isovalent/hubble-fgs/pkg/manager"
)

type KubernetesMetadataService struct {
	manager manager.KubernetesManager
}

func NewKubernetesMetadataService(manager manager.KubernetesManager) (*KubernetesMetadataService, error) {
	return &KubernetesMetadataService{manager}, nil
}

func (m *KubernetesMetadataService) GetLabels() (map[string]string, error) {
	node, err := m.manager.GetControllerManager().GetNode()
	if err != nil {
		return nil, err
	}
	return node.GetLabels(), nil
}
