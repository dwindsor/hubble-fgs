// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("expected client to be non-nil")
	}

	if client.IsConnected() {
		t.Error("new client should not be connected")
	}
}

func TestClient_NotConnected(t *testing.T) {
	client := NewClient()

	// Adjacency should fail when not connected
	_, err := client.Adjacency(context.Background(), &hav1.AdjRequest{})
	if err == nil {
		t.Error("expected error when not connected")
	}
}

func TestClient_CloseWhenNotConnected(t *testing.T) {
	client := NewClient()

	// Close should succeed even when not connected
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

func TestMockClient(t *testing.T) {
	client := NewMockClient()

	// Connect should succeed
	ctx := context.Background()
	if err := client.Connect(ctx, "10.0.0.1:8883"); err != nil {
		t.Errorf("connect failed: %v", err)
	}

	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}

	if client.Address() != "10.0.0.1:8883" {
		t.Errorf("expected address '10.0.0.1:8883', got '%s'", client.Address())
	}

	// Adjacency should succeed with default response
	resp, err := client.Adjacency(ctx, &hav1.AdjRequest{
		HaIp: "10.0.0.2",
	})
	if err != nil {
		t.Errorf("adjacency failed: %v", err)
	}
	if resp.Status != hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS {
		t.Errorf("expected success status, got %v", resp.Status)
	}

	// Close should succeed
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}

	if client.IsConnected() {
		t.Error("expected client to be disconnected after close")
	}
}

func TestMockClient_CustomHandler(t *testing.T) {
	client := NewMockClient()

	// Set custom handler
	expectedDetails := "custom response"
	client.SetAdjacencyHandler(func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
			Details: expectedDetails,
		}, nil
	})

	// Connect
	ctx := context.Background()
	if err := client.Connect(ctx, "10.0.0.1:8883"); err != nil {
		t.Errorf("connect failed: %v", err)
	}

	// Adjacency should use custom handler
	resp, err := client.Adjacency(ctx, &hav1.AdjRequest{})
	if err != nil {
		t.Errorf("adjacency failed: %v", err)
	}
	if resp.Details != expectedDetails {
		t.Errorf("expected details '%s', got '%s'", expectedDetails, resp.Details)
	}
}

func TestWithClientTimeout(t *testing.T) {
	client := NewClient().(*client)

	// Default timeout
	if client.opts.timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", client.opts.timeout)
	}
}

func TestMockClient_NotConnected(t *testing.T) {
	client := NewMockClient()

	// Adjacency should fail when not connected
	_, err := client.Adjacency(context.Background(), &hav1.AdjRequest{})
	if err == nil {
		t.Error("expected error when not connected")
	}
}

// mockClient implements the Client interface for testing.
type mockClient struct {
	mu                sync.RWMutex
	addr              string
	connected         bool
	adjHandler    func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error)
	notifyHandler func(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error)
}

// NewMockClient creates a mock HA client for testing.
func NewMockClient() *mockClient {
	return &mockClient{}
}

// SetAdjacencyHandler sets the handler for Adjacency calls.
func (m *mockClient) SetAdjacencyHandler(handler func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adjHandler = handler
}

// SetNotifyHandler sets the handler for Notify calls.
func (m *mockClient) SetNotifyHandler(handler func(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifyHandler = handler
}

func (m *mockClient) Connect(ctx context.Context, addr string, opts ...ClientOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addr = addr
	m.connected = true
	return nil
}

func (m *mockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *mockClient) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

func (m *mockClient) Address() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addr
}

func (m *mockClient) Adjacency(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
	m.mu.RLock()
	handler := m.adjHandler
	connected := m.connected
	m.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("client is not connected")
	}

	if handler != nil {
		return handler(ctx, req)
	}

	// Default response
	return &hav1.AdjResponse{
		Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
		Details: "Mock adjacency success",
	}, nil
}

func (m *mockClient) Notify(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error) {
	m.mu.RLock()
	handler := m.notifyHandler
	connected := m.connected
	m.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("client is not connected")
	}

	if handler != nil {
		return handler(ctx, req)
	}

	return &hav1.NotifyResponse{
		Status: hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
	}, nil
}

var _ Client = (*mockClient)(nil)
