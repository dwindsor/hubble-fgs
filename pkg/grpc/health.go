package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
)

var (
	grpcHealth = fgs.HealthStatusResult_HEALTH_STATUS_RUNNING
)

func getHealth() (*fgs.GetHealthStatusResponse, error) {
	resp := &fgs.GetHealthStatusResponse{}
	hs := &fgs.HealthStatus{
		Event:   fgs.HealthStatusType_HEALTH_STATUS_TYPE_STATUS,
		Status:  grpcHealth,
		Details: "running",
	}
	resp.HealthStatus = append(resp.HealthStatus, hs)
	return resp, nil
}
