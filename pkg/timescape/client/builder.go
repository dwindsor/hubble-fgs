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
	"time"

	"github.com/cilium/tetragon/pkg/logger"

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
			Timeout: types.DefaultHTTPRequestTimeout,
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

// WithMTLS enables mTLS authentication and sets the kubernetes client
func (b *ClientBuilder) WithMTLS() *ClientBuilder {
	b.config.UseMTLS = true
	return b
}

// WithRequestTimeout sets the HTTP Request timeout in seconds
func (b *ClientBuilder) WithRequestTimeout(timeout time.Duration) *ClientBuilder {
	// Convert to seconds and back to ensure we store in second precision
	seconds := timeout.Seconds()
	b.queueConfig.SendTimeout = time.Duration(seconds) * time.Second
	return b
}

// WithConnectionTimeout sets the connection timeout in seconds for the HTTP transport
func (b *ClientBuilder) WithConnectionTimeout(timeout time.Duration) *ClientBuilder {
	seconds := timeout.Seconds()
	b.config.ConnectionTimeout = time.Duration(seconds) * time.Second
	return b
}

// WithProtobuf enables protobuf serialization instead of JSON
func (b *ClientBuilder) WithProtobuf() *ClientBuilder {
	b.config.UseProtobuf = true
	return b
}

// WithJson enables json serialization
func (b *ClientBuilder) WithJson() *ClientBuilder {
	b.config.UseProtobuf = false
	return b
}

// WithInsecureSkipVerify disables TLS certificate verification (for development only)
func (b *ClientBuilder) WithInsecureSkipVerify() *ClientBuilder {
	b.config.InsecureSkipVerify = true
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

// WithBatchTimeout sets batch timeout configuration
func (b *ClientBuilder) WithBatchTimeout(batchTimeout time.Duration) *ClientBuilder {
	b.queueConfig.BatchTimeout = batchTimeout
	return b
}

// WithCompression enables or disables compression for the client connection.
func (b *ClientBuilder) WithCompression(enabled bool) *ClientBuilder {
	b.config.Compression = enabled
	return b
}

// Build creates the timescape client with queue and transport
func (b *ClientBuilder) Build(ctx context.Context) (types.Client, error) {
	transport, err := NewHTTPTransport(b.config)
	if err != nil {
		return nil, err
	}
	cfg := b.queueConfig
	cfg.Transport = transport
	client, err := NewQueue(ctx, cfg)
	if err != nil {
		return nil, err
	}

	logger.GetLogger().Debug("timescape client created successfully",
		"endpoint", b.config.EndpointURL,
		"useProtobuf", b.config.UseProtobuf,
		"insecureSkipVerify", b.config.InsecureSkipVerify,
		"requestTimeout", b.queueConfig.SendTimeout,
		"connectionTimeout", b.config.ConnectionTimeout,
		"maxRetries", b.queueConfig.MaxRetries,
		"batchTimeout", b.queueConfig.BatchTimeout,
	)
	return client, nil
}
