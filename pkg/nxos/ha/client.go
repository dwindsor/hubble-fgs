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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// Client defines the interface for HA peer communication.
type Client interface {
	// Connect establishes a connection to the peer at the given address.
	Connect(ctx context.Context, addr string, opts ...ClientOption) error

	// Close closes the connection to the peer.
	Close() error

	// IsConnected returns true if the client is connected to a peer.
	IsConnected() bool

	// Address returns the address of the connected peer.
	Address() string

	// Adjacency sends an adjacency request to the peer.
	Adjacency(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error)

	// Notify sends a notification to the peer.
	Notify(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error)
}

// ClientOption configures the HA client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	timeout     time.Duration
	dialOptions []grpc.DialOption
}

// WithClientTimeout sets the timeout for client operations.
func WithClientTimeout(timeout time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.timeout = timeout
	}
}

// WithDialOptions sets additional gRPC dial options.
func WithDialOptions(opts ...grpc.DialOption) ClientOption {
	return func(o *clientOptions) {
		o.dialOptions = append(o.dialOptions, opts...)
	}
}

// client implements the Client interface.
type client struct {
	mu        sync.RWMutex
	conn      *grpc.ClientConn
	haClient  hav1.HaClient
	addr      string
	connected bool
	opts      clientOptions
}

// NewClient creates a new HA client.
func NewClient() Client {
	return &client{
		opts: clientOptions{
			timeout: 10 * time.Second,
		},
	}
}

// Connect establishes a connection to the peer at the given address.
func (c *client) Connect(ctx context.Context, addr string, opts ...ClientOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply options
	for _, opt := range opts {
		opt(&c.opts)
	}

	// Close existing connection if any
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.haClient = nil
		c.connected = false
	}

	// Build dial options
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	dialOpts = append(dialOpts, c.opts.dialOptions...)

	// Create connection with timeout
	dialCtx, cancel := context.WithTimeout(ctx, c.opts.timeout)
	defer cancel()

	logger.GetLogger().Debug("Connecting to HA peer", "addr", addr)

	conn, err := grpc.DialContext(dialCtx, addr, dialOpts...)
	if err != nil {
		logger.GetLogger().Error("Failed to connect to HA peer", logfields.Error, err, "addr", addr)
		return fmt.Errorf("failed to connect to HA peer %s: %w", addr, err)
	}

	c.conn = conn
	c.haClient = hav1.NewHaClient(conn)
	c.addr = addr
	c.connected = true

	logger.GetLogger().Info("Connected to HA peer", "addr", addr)
	return nil
}

// Close closes the connection to the peer.
func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		logger.GetLogger().Debug("Closing HA client connection", "addr", c.addr)
		err := c.conn.Close()
		c.conn = nil
		c.haClient = nil
		c.connected = false
		return err
	}
	return nil
}

// IsConnected returns true if the client is connected to a peer.
func (c *client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Address returns the address of the connected peer.
func (c *client) Address() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.addr
}

// Adjacency sends an adjacency request to the peer.
func (c *client) Adjacency(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
	c.mu.RLock()
	if !c.connected || c.haClient == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client is not connected")
	}
	haClient := c.haClient
	c.mu.RUnlock()

	// Apply timeout if set
	if c.opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.timeout)
		defer cancel()
	}

	return haClient.Adjacency(ctx, req)
}

// Notify sends a notification to the peer.
func (c *client) Notify(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error) {
	c.mu.RLock()
	if !c.connected || c.haClient == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client is not connected")
	}
	haClient := c.haClient
	c.mu.RUnlock()

	if c.opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.timeout)
		defer cancel()
	}

	return haClient.Notify(ctx, req)
}

// Ensure implementation satisfies the interface
var _ Client = (*client)(nil)
