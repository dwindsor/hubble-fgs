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

import (
	"context"
	"testing"
)

func TestReservePort_HAService(t *testing.T) {
	ctx := context.Background()
	s := NewStore(ctx).(*deviceStore)

	port, err := s.ReservePort(HAService)
	if err != nil {
		t.Fatalf("ReservePort(HAService) failed: %v", err)
	}
	if port != s.hsaPortLow+HAServerPortOffset {
		t.Errorf("expected port %d, got %d", s.hsaPortLow+HAServerPortOffset, port)
	}
}

func TestReservePort_UnknownService(t *testing.T) {
	ctx := context.Background()
	s := NewStore(ctx).(*deviceStore)

	_, err := s.ReservePort(ServicePortType(999))
	if err == nil {
		t.Fatal("expected error for unknown service type, got nil")
	}
}

func TestReservePort_ExceedsRange(t *testing.T) {
	ctx := context.Background()
	s := NewStore(ctx).(*deviceStore)

	// Artificially shrink the range so HAServerPortOffset (0) would require
	// the port to be exactly at low; then set low > high to simulate overflow.
	s.mu.Lock()
	s.hsaPortLow = 100
	s.hsaPortHigh = 99 // low > high: any offset causes port > high
	s.mu.Unlock()

	// HAServerPortOffset is 0, so port = 100 > high (99).
	_, err := s.ReservePort(HAService)
	if err == nil {
		t.Fatal("expected error when computed port exceeds HSA port range, got nil")
	}
}
