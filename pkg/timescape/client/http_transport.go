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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

// HTTPTransport implements Transport interface for HTTP endpoints
type HTTPTransport struct {
	config types.HTTPTransportConfig
	client *http.Client
}

// NewHTTPTransport creates a new HTTP transport with the given configuration
func NewHTTPTransport(config types.HTTPTransportConfig) *HTTPTransport {
	if config.Timeout == 0 {
		config.Timeout = types.DefaultHTTPTimeout
	}

	// Create HTTP transport with connection pooling and keep-alive
	transport := createOptimizedTransport(config)

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	return &HTTPTransport{
		config: config,
		client: client,
	}
}

func (h *HTTPTransport) Name() string {
	return h.config.EndpointURL
}

// newTracedClient creates a new HTTP client with tracing capabilities
func (h *HTTPTransport) newTracedClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			ServerName:         "", // Empty to skip hostname verification
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
	}
	return &http.Client{
		Timeout:   types.DefaultHTTPTimeout,
		Transport: tr,
	}
}

// DoWithTrace performs an HTTP request with detailed tracing. Use for development/debugging only.
func (h *HTTPTransport) DoWithTrace(req *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) { logger.GetLogger().Info("GetConn", "hostPort", hostPort) },
		GotConn: func(info httptrace.GotConnInfo) {
			logger.GetLogger().Info("GotConn", "reused", info.Reused, "idle", info.WasIdle, "conn", info.Conn.LocalAddr())
		},
		DNSStart: func(info httptrace.DNSStartInfo) { logger.GetLogger().Info("DNSStart", "host", info.Host) },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			logger.GetLogger().Info("DNSDone", "addrs", info.Addrs, "err", info.Err, "coalesced", info.Coalesced)
		},
		ConnectStart: func(network, addr string) {
			logger.GetLogger().Info("ConnectStart", "network", network, "addr", addr, "time_now", time.Now().Format(time.RFC3339Nano))
		},
		ConnectDone: func(network, addr string, err error) {
			logger.GetLogger().Info("ConnectDone", "network", network, "addr", addr, "err", err, "time_now", time.Now().Format(time.RFC3339Nano))
		},
		TLSHandshakeStart: func() {
			logger.GetLogger().Info("TLSHandshakeStart", "time_now", time.Now().Format(time.RFC3339Nano))
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			logger.GetLogger().Info("TLSHandshakeDone", "err", err, "time_now", time.Now().Format(time.RFC3339Nano))
		},
		GotFirstResponseByte: func() {
			logger.GetLogger().Info("GotFirstResponseByte", "time_now", time.Now().Format(time.RFC3339Nano))
		},
		WroteHeaders: func() {
			logger.GetLogger().Info("WroteHeaders", "time_now", time.Now().Format(time.RFC3339Nano))
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			logger.GetLogger().Info("WroteRequest", "err", info.Err, "time_now", time.Now().Format(time.RFC3339Nano))
		},
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	return h.newTracedClient().Do(req)
}

func (h *HTTPTransport) PushBatch(ctx context.Context, msgs []types.Msg) error {
	if len(msgs) == 0 {
		return nil
	}

	logger.GetLogger().Info("HTTP transport preparing to send batch",
		"count", len(msgs),
		"endpoint", h.config.EndpointURL,
	)

	// Create payload with system_status top-level key
	var reqBody []byte
	var err error

	// Configure protobuf JSON marshaler to use enum integers
	marshaler := protojson.MarshalOptions{
		UseEnumNumbers:  true, // This makes enums serialize as integers
		EmitUnpopulated: false,
		Indent:          "",
		UseProtoNames:   true,
	}

	if len(msgs) == 1 {
		// For single messages, wrap in system_status
		// Event is already a protobuf message (*v1alpha.SystemStatusEvent)
		eventJSON, err := marshaler.Marshal(msgs[0].Event)
		if err != nil {
			return fmt.Errorf("failed to marshal protobuf event: %w", err)
		}
		// Create wrapper with system_status key
		reqBody = []byte(fmt.Sprintf(`{"system_status":%s}`, string(eventJSON)))
	} else {
		// For multiple messages, create array with system_status wrapper
		var events []string
		for _, msg := range msgs {
			// Event is already a protobuf message (*v1alpha.SystemStatusEvent)
			eventJSON, err := marshaler.Marshal(msg.Event)
			if err != nil {
				return fmt.Errorf("failed to marshal protobuf event: %w", err)
			}
			events = append(events, fmt.Sprintf(`{"system_status":%s}`, string(eventJSON)))
		}
		reqBody = []byte("[" + events[0])
		for i := 1; i < len(events); i++ {
			reqBody = append(reqBody, []byte(","+events[i])...)
		}
		reqBody = append(reqBody, ']')
	}
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Log the full payload for debugging
	logger.GetLogger().Info("HTTP transport payload",
		"count", len(msgs),
		"endpoint", h.config.EndpointURL,
		"payload", string(reqBody),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.EndpointURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add query parameter
	q := req.URL.Query()
	q.Add("object_type", "OBJECT_TYPE_SYSTEM_STATUS_EVENT")
	req.URL.RawQuery = q.Encode()

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "timescape-client/1.0")

	// Add basic authentication if configured
	if h.config.Username != "" && h.config.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(h.config.Username + ":" + h.config.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	// Send request and measure latency with tracing
	start := time.Now()
	resp, err := h.client.Do(req)
	// Uncomment the line below to use traced client for transport debugging in development
	// resp, err := h.DoWithTrace(req)
	latency := time.Since(start)

	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)

	}
	defer resp.Body.Close()

	// Check HTTP status codes - return error for non-2xx
	// 200-299 are success codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			logger.GetLogger().Info("Response body for error", "status", resp.StatusCode, "body", string(body))
		}
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	// Log successful HTTP response
	logger.GetLogger().Info("HTTP transport push successful",
		"status_code", resp.StatusCode,
		"status", resp.Status,
		"count", len(msgs),
		"latency_ms", latency.Milliseconds(),
		"endpoint", h.config.EndpointURL,
	)

	return nil
}

// createOptimizedTransport creates an HTTP transport that uses a single persistent connection
func createOptimizedTransport(config types.HTTPTransportConfig) *http.Transport {
	transport := &http.Transport{
		// Single persistent connection configuration
		MaxIdleConns:        1, // Only 1 idle connection total
		MaxIdleConnsPerHost: 1, // Only 1 idle connection per host
		MaxConnsPerHost:     1, // Only 1 total connection per host
		IdleConnTimeout:     0, // Never timeout idle connections (keep forever)

		// Keep-alive settings for persistent connection
		DisableKeepAlives:     false,            // Enable keep-alive
		ResponseHeaderTimeout: 30 * time.Second, // Response header timeout
		ExpectContinueTimeout: 2 * time.Second,  // Expect: 100-continue timeout

		// Optimize for single connection
		ForceAttemptHTTP2:  true,                // Try HTTP/2 for better multiplexing
		DisableCompression: !config.Compression, // Enable/disable compression based on config
	}

	// Only configure TLS if needed for HTTPS (future use).
	// Can use cert package in pkg/cert for loading certs if needed.
	if config.InsecureSkipVerify || config.CertFile != "" || config.KeyFile != "" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
			ServerName:         config.ServerName,
		}

		// Future: Add mTLS support here when certificates are provided
		transport.TLSClientConfig = tlsConfig
		transport.TLSHandshakeTimeout = 10 * time.Second
	}

	return transport
}
