// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package device

import "fmt"

// ServicePortType identifies a service that requires a port within the HSA range.
type ServicePortType int

const (
	// HAService is the High Availability gRPC service.
	HAService ServicePortType = iota
)

// Port offsets from the HSA port range start. Each service gets a fixed offset
// so that port allocation is predictable and stable across restarts.
const (
	// HAServerPortOffset is the offset for the HA gRPC service.
	HAServerPortOffset uint16 = 0
)

// ReservePort returns the port for the given service type within the HSA range.
// The port is computed as hsaPortLow + serviceOffset.
// Returns an error if the service type is unknown or the computed port exceeds hsaPortHigh.
func (s *deviceStore) ReservePort(serviceType ServicePortType) (uint16, error) {
	s.mu.RLock()
	low := s.hsaPortLow
	high := s.hsaPortHigh
	s.mu.RUnlock()

	var offset uint16
	switch serviceType {
	case HAService:
		offset = HAServerPortOffset
	default:
		return 0, fmt.Errorf("unknown service type %d: no port offset defined", serviceType)
	}

	port := low + offset
	if port > high {
		return 0, fmt.Errorf("computed port %d for service type %d exceeds HSA port range [%d, %d]", port, serviceType, low, high)
	}
	return port, nil
}
