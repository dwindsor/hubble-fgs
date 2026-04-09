//go:build nok8s

package local

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

type MetadataService interface {
	GetLabels(ctx context.Context) (map[string]string, error)
}

func GetMetadataService() (MetadataService, error) {
	switch {
	case option.Config.Environment == option.EnvironmentAWS:
		return NewAWSMetadataService()
	default:
		return &NoopMetadataService{}, nil
	}
}
