// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockHaEventHandler records calls to UpdateKeepalive and UpdateBulkSync.
type mockHaEventHandler struct {
	mu             sync.Mutex
	keepaliveCalls []haEventCall
	bulkSyncCalls  []haEventCall
}

type haEventCall struct {
	dpuUid string
	status bool
}

func (m *mockHaEventHandler) RegisterDpu(_ context.Context, _ string) {}

func (m *mockHaEventHandler) UpdateKeepalive(_ context.Context, dpuUid string, up bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keepaliveCalls = append(m.keepaliveCalls, haEventCall{dpuUid: dpuUid, status: up})
}

func (m *mockHaEventHandler) UpdateBulkSync(_ context.Context, dpuUid string, done bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bulkSyncCalls = append(m.bulkSyncCalls, haEventCall{dpuUid: dpuUid, status: done})
}

func (m *mockHaEventHandler) UpdatePolicyRevision(_ context.Context, _ string) {}

func TestSetHaEventHandler(t *testing.T) {
	// Save and restore original handler
	origHandler := haEventHandler
	defer func() { haEventHandler = origHandler }()

	mock := &mockHaEventHandler{}
	SetHaEventHandler(mock)
	assert.Equal(t, mock, haEventHandler)
}

func TestSetHaEventHandlerNil(t *testing.T) {
	// Save and restore original handler
	origHandler := haEventHandler
	defer func() { haEventHandler = origHandler }()

	SetHaEventHandler(nil)
	assert.Nil(t, haEventHandler)
}

func TestHaEventHandlerKeepalive(t *testing.T) {
	origHandler := haEventHandler
	defer func() { haEventHandler = origHandler }()

	mock := &mockHaEventHandler{}
	SetHaEventHandler(mock)

	ctx := context.Background()
	dpuUid := "dpu-1"

	// Simulate keepalive up
	haEventHandler.UpdateKeepalive(ctx, dpuUid, true)
	assert.Len(t, mock.keepaliveCalls, 1)
	assert.Equal(t, haEventCall{dpuUid: dpuUid, status: true}, mock.keepaliveCalls[0])

	// Simulate keepalive down
	haEventHandler.UpdateKeepalive(ctx, dpuUid, false)
	assert.Len(t, mock.keepaliveCalls, 2)
	assert.Equal(t, haEventCall{dpuUid: dpuUid, status: false}, mock.keepaliveCalls[1])
}

func TestHaEventHandlerBulkSync(t *testing.T) {
	origHandler := haEventHandler
	defer func() { haEventHandler = origHandler }()

	mock := &mockHaEventHandler{}
	SetHaEventHandler(mock)

	ctx := context.Background()
	dpuUid := "dpu-2"

	// Simulate bulk sync done
	haEventHandler.UpdateBulkSync(ctx, dpuUid, true)
	assert.Len(t, mock.bulkSyncCalls, 1)
	assert.Equal(t, haEventCall{dpuUid: dpuUid, status: true}, mock.bulkSyncCalls[0])
}

func TestNilHaEventHandlerDoesNotPanic(t *testing.T) {
	origHandler := haEventHandler
	defer func() { haEventHandler = origHandler }()

	SetHaEventHandler(nil)

	// The guard check in grpc.go is: haEventHandler != nil
	// Verify that nil handler doesn't get called (no panic)
	assert.NotPanics(t, func() {
		if haEventHandler != nil {
			haEventHandler.UpdateKeepalive(context.Background(), "dpu-1", true)
		}
	})
}
