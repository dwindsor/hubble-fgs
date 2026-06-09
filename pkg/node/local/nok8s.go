//go:build nok8s

package local

import (
	"context"
)

type MetadataService interface {
	GetLabels(ctx context.Context) (map[string]string, error)
}

// Cloud-provider routing is gated by the separate nocloud tag, not nok8s. In a
// plain nok8s build cloud metadata is still available; in the slim nok8s,nocloud
// build the stub reports no cloud environment and we fall back to the no-op
// service.
func GetMetadataService() (MetadataService, error) {
	if svc, ok, err := getCloudMetadataService(); ok {
		return svc, err
	}
	return &NoopMetadataService{}, nil
}
