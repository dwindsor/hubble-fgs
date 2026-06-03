//go:build nok8s

package local

import (
	"context"
)

type MetadataService interface {
	GetLabels(ctx context.Context) (map[string]string, error)
}

// The slim nok8s build drops the AWS SDK, so AWS instance metadata is
// unavailable here; all environments fall back to the no-op service.
func GetMetadataService() (MetadataService, error) {
	return &NoopMetadataService{}, nil
}
