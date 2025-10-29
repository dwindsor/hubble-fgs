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
)

type NoopMetadataService struct {
}

func (n *NoopMetadataService) GetHostname(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetInstanceId(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetInternalIP(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetExternalIP(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetInternalDNS(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetExternalDNS(ctx context.Context) (string, error) {
	return "", nil
}

func (n *NoopMetadataService) GetLabels(_ context.Context) (map[string]string, error) {
	return nil, nil
}
