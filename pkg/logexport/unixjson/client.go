// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package unixjson

import (
	"encoding/json"
	"net"
	"sync"
)

// Client writes JSON messages to a unixgram socket.
type Client struct {
	socketPath string
	conn       *net.UnixConn
	mu         sync.Mutex
	connected  bool
}

// NewClient creates a new unixgram JSON client.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
	}
}

// Connect establishes a connection to the unix socket.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connect()
}

func (c *Client) connect() error {
	if c.connected {
		return nil
	}

	addr, err := net.ResolveUnixAddr("unixgram", c.socketPath)
	if err != nil {
		return err
	}

	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}

	c.conn = conn
	c.connected = true
	return nil
}

func (c *Client) closeConnection() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
}

// Close closes the unix socket connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	c.closeConnection()
	return nil
}

// IsConnected reports whether the client currently has an open socket.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Write marshals message to JSON and writes it to the unixgram socket.
func (c *Client) Write(message any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Existing event logger behavior is to connect/write/close each message.
	// Keep the same semantics for callers that may rely on it.
	if err := c.connect(); err != nil {
		return err
	}
	defer c.closeConnection()

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(jsonMessage)
	return err
}
