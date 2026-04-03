// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package timescape provides a client library for sending events to the timescape service.
//
// The timescape package offers a prioritized queuing system for sending system status
// and policy status events to a timescape ingester service over HTTP. It features:
//
//   - Priority-based message queuing (high, low priorities)
//   - Automatic batching for non-critical messages
//   - Connection validation and retry logic with exponential backoff
//   - Singleton client pattern for application-wide usage
//   - Support for both JSON and protobuf serialization

package timescape

import (
	"context"
	"sync"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/timescape/client"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

// Singleton instance management
var (
	timescapeClient types.Client
	clientOnce      sync.Once
	clientErr       error
)

// GetTimescapeClient creates a singleton timescape client with default HTTP transport
func NewTimescapeClient(ctx context.Context, config types.HTTPTransportConfig, batchTimeoutMs uint32) (types.Client, error) {
	clientOnce.Do(func() {
		builder := client.NewClientBuilder().
			WithEndpoint(config.EndpointURL).
			WithRequestTimeout(config.Timeout).
			WithConnectionTimeout(config.ConnectionTimeout).
			WithRetryConfig(config.MaxRetries, types.DefaultBaseBackoff).
			WithBatchTimeout(time.Duration(batchTimeoutMs)*time.Millisecond).
			WithCompression(config.Compression)

		// Set authentication method based on configuration
		if config.UseMTLS {
			builder = builder.WithMTLS()
		} else {
			// Use BasicAuth for non-mTLS authentication
			builder = builder.WithAuth(config.Username, config.Password)
		}

		// Set Protobuf or JSON serialization
		if config.UseProtobuf {
			builder = builder.WithProtobuf()
		} else {
			builder = builder.WithJson()
		}

		// Set TLS configurations
		if config.InsecureSkipVerify {
			builder = builder.WithInsecureSkipVerify()
		}

		var err error
		timescapeClient, err = builder.Build(ctx)
		if err != nil {
			clientErr = err
			return
		}
		clientErr = nil
	})

	if clientErr != nil {
		return nil, clientErr
	}

	return timescapeClient, nil
}
