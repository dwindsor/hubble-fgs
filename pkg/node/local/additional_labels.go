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
	"context"
	"maps"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

type additionalLabelsMetadataService struct {
	MetadataService
	warnedKeys map[string]struct{}
}

func withAdditionalNodeLabels(metadata MetadataService) MetadataService {
	if len(option.Config.AdditionalNodeLabels) == 0 {
		return metadata
	}
	return &additionalLabelsMetadataService{MetadataService: metadata, warnedKeys: make(map[string]struct{})}
}

func (m *additionalLabelsMetadataService) GetLabels(ctx context.Context) (map[string]string, error) {
	labels := maps.Clone(option.Config.AdditionalNodeLabels)
	metadataLabels, err := m.MetadataService.GetLabels(ctx)
	if err != nil {
		return nil, err
	}
	for key, value := range metadataLabels {
		if _, ok := labels[key]; ok {
			if _, warned := m.warnedKeys[key]; !warned {
				logger.GetLogger().Warn("locally configured additional node label overridden by metadata service label", "label", key)
				m.warnedKeys[key] = struct{}{}
			}
		}
		labels[key] = value
	}
	return labels, nil
}
