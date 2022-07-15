//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package health

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	grpcHealth = tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING
)

func GetHealth() (*tetragon.GetHealthStatusResponse, error) {
	resp := &tetragon.GetHealthStatusResponse{}
	hs := &tetragon.HealthStatus{
		Event:   tetragon.HealthStatusType_HEALTH_STATUS_TYPE_STATUS,
		Status:  grpcHealth,
		Details: "running",
	}
	resp.HealthStatus = append(resp.HealthStatus, hs)
	return resp, nil
}
