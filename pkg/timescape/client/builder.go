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
	"os"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

// ClientBuilder provides an interface for building timescape client
type ClientBuilder struct {
	config      types.HTTPTransportConfig
	queueConfig types.Config
}

// NewClientBuilder creates a new client builder with sensible defaults
func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{
		config: types.HTTPTransportConfig{
			Timeout: types.DefaultHTTPTimeout,
		},
		queueConfig: types.DefaultConfig(),
	}
}

// WithEndpoint sets the timescape endpoint URL
func (b *ClientBuilder) WithEndpoint(url string) *ClientBuilder {
	b.config.EndpointURL = url
	return b
}

// WithAuth sets basic authentication credentials
func (b *ClientBuilder) WithAuth(username, password string) *ClientBuilder {
	b.config.Username = username
	b.config.Password = password
	return b
}

// WithAuthFromEnv sets basic authentication from environment variables
func (b *ClientBuilder) WithAuthFromEnv() *ClientBuilder {
	b.config.Username = os.Getenv("TIMESCAPE_USERNAME")
	b.config.Password = os.Getenv("TIMESCAPE_PASSWORD")
	return b
}

// WithTimeout sets the HTTP timeout
func (b *ClientBuilder) WithTimeout(timeout time.Duration) *ClientBuilder {
	b.config.Timeout = timeout
	return b
}

// WithProtobuf enables protobuf serialization instead of JSON
func (b *ClientBuilder) WithProtobuf() *ClientBuilder {
	b.config.UseProtobuf = true
	return b
}

// WithProtobuf enables json serialization
func (b *ClientBuilder) WithJson() *ClientBuilder {
	b.config.UseProtobuf = false
	return b
}

// WithInsecureSkipVerify disables TLS certificate verification (for development only)
func (b *ClientBuilder) WithInsecureSkipVerify() *ClientBuilder {
	b.config.InsecureSkipVerify = true
	return b
}

// WithServerName sets the server name for TLS verification in the client configuration.
func (b *ClientBuilder) WithServerName(serverName string) *ClientBuilder {
	b.config.ServerName = serverName
	return b
}

// WithQueueConfig sets custom queue configuration
func (b *ClientBuilder) WithQueueConfig(cfg types.Config) *ClientBuilder {
	b.queueConfig = cfg
	return b
}

// WithRetryConfig sets retry configuration
func (b *ClientBuilder) WithRetryConfig(maxRetries int, baseBackoff time.Duration) *ClientBuilder {
	b.queueConfig.MaxRetries = maxRetries
	b.queueConfig.BaseBackoff = baseBackoff
	return b
}

// WithCompression enables or disables compression for the client connection.
func (b *ClientBuilder) WithCompression(enabled bool) *ClientBuilder {
	b.config.Compression = enabled
	return b
}

// Build creates the timescape client with queue and transport
func (b *ClientBuilder) Build(ctx context.Context) (types.Client, error) {
	transport := NewHTTPTransport(b.config)
	cfg := b.queueConfig
	cfg.Transport = transport
	client, err := NewQueue(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return client, nil
}
