// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	systemstatus "github.com/isovalent/ipa/system_status/v1alpha"
)

const (
	ENDPOINTURL = "https://example.com:4260/push"
	USERNAME    = "test"
	PASSWORD    = "pass"
)

func TestNewHTTPTransport(t *testing.T) {
	tests := []struct {
		name           string
		config         types.HTTPTransportConfig
		expectedName   string
		validateClient func(t *testing.T, transport *HTTPTransport)
	}{
		{
			name: "default_configuration",
			config: types.HTTPTransportConfig{
				EndpointURL: ENDPOINTURL,
				Username:    USERNAME,
				Password:    PASSWORD,
			},
			expectedName: ENDPOINTURL,
			validateClient: func(t *testing.T, transport *HTTPTransport) {
				assert.Equal(t, types.DefaultHTTPTimeout, transport.client.Timeout)
				assert.Equal(t, ENDPOINTURL, transport.config.EndpointURL)
			},
		},
		{
			name: "custom_timeout",
			config: types.HTTPTransportConfig{
				EndpointURL: ENDPOINTURL,
				Timeout:     10 * time.Second,
				Compression: true,
			},
			expectedName: ENDPOINTURL,
			validateClient: func(t *testing.T, transport *HTTPTransport) {
				assert.Equal(t, 10*time.Second, transport.client.Timeout)
				assert.True(t, transport.config.Compression)
			},
		},
		{
			name: "insecure_skip_verify",
			config: types.HTTPTransportConfig{
				EndpointURL:        ENDPOINTURL,
				InsecureSkipVerify: true,
			},
			expectedName: ENDPOINTURL,
			validateClient: func(t *testing.T, transport *HTTPTransport) {
				assert.True(t, transport.config.InsecureSkipVerify)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := NewHTTPTransport(tt.config)

			require.NotNil(t, transport)
			assert.Equal(t, tt.expectedName, transport.Name())
			assert.NotNil(t, transport.client)

			if tt.validateClient != nil {
				tt.validateClient(t, transport)
			}
		})
	}
}

func TestHTTPTransport_PushBatch_SingleMessage(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "timescape-client/1.0", r.Header.Get("User-Agent"))

		// Read and verify body structure
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var payload map[string]interface{}
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		// Verify system_status wrapper
		assert.Contains(t, payload, "system_status")
		systemStatus := payload["system_status"].(map[string]interface{})
		assert.Contains(t, systemStatus, "time")
		assert.Contains(t, systemStatus, "status")

		// Verify inner status structure
		status := systemStatus["status"].(map[string]interface{})
		assert.Contains(t, status, "cluster_name")
		assert.Equal(t, "smartswitch", status["cluster_name"])
		assert.Equal(t, "serial-1234", status["node_name"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL + "/push",
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	// Create test message
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestSystemStatusEvent(t),
	}

	ctx := context.Background()
	err := transport.PushBatch(ctx, []types.Msg{msg})
	assert.NoError(t, err)
}

func TestHTTPTransport_PushBatch_MultipleBatch(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read and verify body structure
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var payload []map[string]interface{}
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		// Verify we have multiple messages
		assert.Len(t, payload, 2)

		// Verify each message has system_status wrapper
		for _, item := range payload {
			assert.Contains(t, item, "system_status")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL + "/push",
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	// Create test messages
	msgs := []types.Msg{
		{
			ID:       uuid.New().String(),
			Priority: types.PriorityHigh,
			Event:    createTestSystemStatusEvent(t),
		},
		{
			ID:       uuid.New().String(),
			Priority: types.PriorityLow,
			Event:    createTestSystemStatusEvent(t),
		},
	}

	ctx := context.Background()
	err := transport.PushBatch(ctx, msgs)
	assert.NoError(t, err)
}

func TestHTTPTransport_PushBatch_PolicyEvent(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read and verify body structure
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var payload map[string]interface{}
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		// Verify system_status wrapper
		assert.Contains(t, payload, "system_status")
		systemStatus := payload["system_status"].(map[string]interface{})
		assert.Contains(t, systemStatus, "time")
		assert.Contains(t, systemStatus, "policy")

		// Verify inner policy structure
		policy := systemStatus["policy"].(map[string]interface{})
		assert.Contains(t, policy, "cluster_name")
		assert.Equal(t, "smartswitch", policy["cluster_name"])
		assert.Contains(t, policy, "node_name")
		assert.Equal(t, "serial-1234", policy["node_name"])
		assert.Contains(t, policy, "statuses")

		// Verify policy statuses array
		statuses := policy["statuses"].([]interface{})
		assert.Len(t, statuses, 1)

		status := statuses[0].(map[string]interface{})
		assert.Contains(t, status, "id")
		assert.Equal(t, "rule-1", status["id"])
		assert.Contains(t, status, "name")
		assert.Equal(t, "test-network-policy", status["name"])
		assert.Contains(t, status, "namespace")
		assert.Equal(t, "default", status["namespace"])
		assert.Contains(t, status, "version")
		assert.Equal(t, "v1.0.0", status["version"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL + "/push",
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestPolicyStatusEvent(t),
	}

	ctx := context.Background()
	err := transport.PushBatch(ctx, []types.Msg{msg})
	assert.NoError(t, err)
}

func TestHTTPTransport_PushBatch_BasicAuth(t *testing.T) {
	expectedUsername := USERNAME
	expectedPassword := PASSWORD

	// Create a test server that checks basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(authHeader, "Basic "))

		// Decode and verify credentials
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)

		credentials := string(decoded)
		assert.Equal(t, expectedUsername+":"+expectedPassword, credentials)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL + "/push",
		Username:    expectedUsername,
		Password:    expectedPassword,
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestSystemStatusEvent(t),
	}

	ctx := context.Background()
	err := transport.PushBatch(ctx, []types.Msg{msg})
	assert.NoError(t, err)
}

func TestHTTPTransport_PushBatch_EmptyBatch(t *testing.T) {
	config := types.HTTPTransportConfig{
		EndpointURL: ENDPOINTURL,
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	ctx := context.Background()
	err := transport.PushBatch(ctx, []types.Msg{})
	assert.NoError(t, err) // Should return nil for empty batch
}

func TestHTTPTransport_PushBatch_HTTPErrors(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		expectError bool
	}{
		{"success_200", http.StatusOK, false},
		{"success_201", http.StatusCreated, false},
		{"success_204", http.StatusNoContent, false},
		{"client_error_400", http.StatusBadRequest, true},
		{"client_error_401", http.StatusUnauthorized, true},
		{"client_error_404", http.StatusNotFound, true},
		{"server_error_500", http.StatusInternalServerError, true},
		{"server_error_503", http.StatusServiceUnavailable, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode >= 400 {
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(`{"error":"test error response"}`))
				} else {
					w.WriteHeader(tt.statusCode)
				}
			}))
			defer server.Close()

			config := types.HTTPTransportConfig{
				EndpointURL: server.URL,
				Timeout:     5 * time.Second,
			}
			transport := NewHTTPTransport(config)

			msg := types.Msg{
				ID:       uuid.New().String(),
				Priority: types.PriorityHigh,
				Event:    createTestSystemStatusEvent(t),
			}

			ctx := context.Background()
			err := transport.PushBatch(ctx, []types.Msg{msg})

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("HTTP error %d", tt.statusCode))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPTransport_PushBatch_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL,
		Timeout:     5 * time.Second,
	}
	transport := NewHTTPTransport(config)

	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestSystemStatusEvent(t),
	}

	// Create a context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := transport.PushBatch(ctx, []types.Msg{msg})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestHTTPTransport_PushBatch_NetworkError(t *testing.T) {
	// Use an invalid URL to trigger network error
	config := types.HTTPTransportConfig{
		EndpointURL: "http://127.0.0.1:99999", // Invalid port
		Timeout:     1 * time.Second,
	}
	transport := NewHTTPTransport(config)

	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestSystemStatusEvent(t),
	}

	ctx := context.Background()
	err := transport.PushBatch(ctx, []types.Msg{msg})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}

func TestHTTPTransport_Name(t *testing.T) {
	config := types.HTTPTransportConfig{
		EndpointURL: ENDPOINTURL,
	}
	transport := NewHTTPTransport(config)

	assert.Equal(t, ENDPOINTURL, transport.Name())
}

func TestCreateOptimizedTransport(t *testing.T) {
	tests := []struct {
		name     string
		config   types.HTTPTransportConfig
		validate func(t *testing.T, transport *http.Transport)
	}{
		{
			name: "basic_configuration",
			config: types.HTTPTransportConfig{
				Compression: true,
			},
			validate: func(t *testing.T, transport *http.Transport) {
				assert.Equal(t, 1, transport.MaxIdleConns)
				assert.Equal(t, 1, transport.MaxIdleConnsPerHost)
				assert.Equal(t, 1, transport.MaxConnsPerHost)
				assert.Equal(t, time.Duration(0), transport.IdleConnTimeout)
				assert.False(t, transport.DisableKeepAlives)
				assert.False(t, transport.DisableCompression)
				assert.True(t, transport.ForceAttemptHTTP2)
			},
		},
		{
			name: "tls_configuration",
			config: types.HTTPTransportConfig{
				InsecureSkipVerify: true,
				ServerName:         "custom-server.com",
			},
			validate: func(t *testing.T, transport *http.Transport) {
				require.NotNil(t, transport.TLSClientConfig)
				assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
				assert.Equal(t, "custom-server.com", transport.TLSClientConfig.ServerName)
				assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
			},
		},
		{
			name: "compression_disabled",
			config: types.HTTPTransportConfig{
				Compression: false,
			},
			validate: func(t *testing.T, transport *http.Transport) {
				assert.True(t, transport.DisableCompression)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := createOptimizedTransport(tt.config)
			require.NotNil(t, transport)

			if tt.validate != nil {
				tt.validate(t, transport)
			}
		})
	}
}

func TestHTTPTransport_DoWithTrace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := types.HTTPTransportConfig{
		EndpointURL: server.URL,
	}
	transport := NewHTTPTransport(config)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := transport.DoWithTrace(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

// Helper functions to create test events
func createTestSystemStatusEvent(_ *testing.T) *systemstatus.SystemStatusEvent {
	now := time.Now()
	return &systemstatus.SystemStatusEvent{
		Time: timestamppb.New(now),
		Event: &systemstatus.SystemStatusEvent_Status{
			Status: &systemstatus.SystemStatusUpdate{
				ClusterName: "smartswitch",
				NodeName:    "serial-1234",
				System: &systemstatus.SystemID{
					Name:    "test-system",
					Version: "1.0.0",
				},
				StartedAt:       timestamppb.New(now),
				TotalConditions: 1,
				FailingConditions: []*systemstatus.FailingCondition{
					{
						ConditionId: "test-condition",
						Severity:    1,
						Message:     "Failure message",
					},
				},
			},
		},
	}
}

func createTestPolicyStatusEvent(_ *testing.T) *systemstatus.SystemStatusEvent {
	now := time.Now()
	return &systemstatus.SystemStatusEvent{
		Time: timestamppb.New(now),
		Event: &systemstatus.SystemStatusEvent_Policy{
			Policy: &systemstatus.PolicyStatusUpdate{
				ClusterName: "smartswitch",
				NodeName:    "serial-1234",
				Statuses: []*systemstatus.PolicyStatus{
					{
						Type:      systemstatus.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
						Id:        "rule-1",
						Name:      "test-network-policy",
						Namespace: "default",
						Version:   "v1.0.0",
					},
				},
			},
		},
	}
}
