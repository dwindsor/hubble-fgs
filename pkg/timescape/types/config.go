// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"context"
	"time"

	systemstatus "github.com/isovalent/ipa/system_status/v1alpha"
)

const (
	// DefaultHTTPRequestTimeout is the default HTTP timeout for timescape client
	DefaultHTTPRequestTimeout            = 60 * time.Second
	DefaultHTTPConnectionTimeout         = 30 * time.Second
	DefaultMaxRetries                    = 3
	DefaultBaseBackoff                   = 100 * time.Millisecond
	DefaultPolicyStatusReportingInterval = 15 * time.Minute
	DefaultTLSHandshakeTimeout           = 20 * time.Second
	DefaultInsecureSkipVerify            = true // For development only; always verify in production
)

// Transport defines the interface for sending messages to timescape
type Transport interface {
	// PushBatch sends a batch of messages; returns error on failure
	PushBatch(ctx context.Context, msgs []Msg) error
	// Name returns the transport name for logging
	Name() string
}

// Client provides the main interface for sending events to timescape
type Client interface {
	// Send queues an event for delivery with specified priority
	Send(ctx context.Context, event *systemstatus.SystemStatusEvent, priority Priority) ErrorCode
	// Close gracefully shuts down the client
	Close() error
}

// Config holds configuration for the timescape client
type Config struct {
	BatchTimeout time.Duration // e.g., 200ms (for low priority queue only)
	SendTimeout  time.Duration // Timeout for individual send operations
	MaxRetries   int           // Maximum retry attempts with exponential backoff
	BaseBackoff  time.Duration // Base delay for exponential backoff (e.g., 100ms)

	Transport Transport // Transport implementation
}

// HTTPTransportConfig holds HTTP-specific transport configuration
type HTTPTransportConfig struct {
	// Timescape server endpoint URL
	EndpointURL string

	// Basic Authentication (current implementation)
	Username string
	Password string

	// mTLS Authentication
	UseMTLS bool // Enable mTLS authentication

	Timeout     time.Duration
	Compression bool
	UseProtobuf bool // if false, use JSON

	// Connection timeout settings
	ConnectionTimeout time.Duration // TCP connection timeout

	// Retry configurations
	MaxRetries int // Maximum number of retry attempts

	// TLS settings
	InsecureSkipVerify bool // For development/testing only
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() Config {
	return Config{
		BatchTimeout: DefaultPolicyStatusReportingInterval,
		SendTimeout:  DefaultHTTPRequestTimeout,
		MaxRetries:   DefaultMaxRetries,
		BaseBackoff:  DefaultBaseBackoff,
	}
}
