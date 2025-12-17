// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package socket

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const (
	MaxConnectRetry = 5
)

// Returns a newly created dataplane socket object
//
// Parameters:
//   - sockFile: string
//   - timeout: time.Duration
func NewDataplaneSocket(sockFile string, timeout time.Duration) *DataplaneSocket {
	return &DataplaneSocket{
		sockFile: sockFile,
		timeout:  timeout,
	}
}

// DataplaneSocket represents a Unix domain socket (UDS) connection
// between the CPA and the dataplane.  It is used to send and
// receive control messages to a single socket.
type DataplaneSocket struct {
	sockFile string
	timeout  time.Duration
	conn     net.Conn
	cancel   context.CancelFunc
	encode   *json.Encoder
	decode   *json.Decoder
}

func (s *DataplaneSocket) Dial(ctx context.Context) error {
	var err error
	retries := 0
	backoff := 1 * time.Second

	// Resolving the socket address
	addr, err := net.ResolveUnixAddr("unix", s.sockFile)
	if err != nil {
		return fmt.Errorf("failed to resolve socket: %w", err)
	}
	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	for {
		s.conn, err = dialer.DialContext(ctx, "unix", addr.String())
		if err == nil {
			return nil
		}
		retries++
		if retries > MaxConnectRetry {
			return fmt.Errorf("dataplane connect failed after %d retries: %w", MaxConnectRetry, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func (s *DataplaneSocket) Connect() error {
	// Setting cancel channel for the connection
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	if err := s.Dial(ctx); err != nil {
		return err
	}

	// Creating json encoder and decoder for the connection
	s.encode = json.NewEncoder(s.conn)
	s.decode = json.NewDecoder(s.conn)
	return nil
}

func (s *DataplaneSocket) Close() error {
	if s.conn == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	err := s.conn.Close()
	s.conn = nil
	s.encode = nil
	s.decode = nil
	return err
}

func (s *DataplaneSocket) Send(msg *ControlMessage) error {
	if s.encode == nil || s.conn == nil {
		return fmt.Errorf("socket not connected")
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}
	return s.encode.Encode(msg)
}

func (s *DataplaneSocket) Receive() (*ControlResponse, error) {
	if s.decode == nil || s.conn == nil {
		return nil, fmt.Errorf("socket not connected")
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	var msg ControlResponse
	err := s.decode.Decode(&msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Formats and prints a control response in a pretty format
// or as raw JSON.
func PrintResponse(ret *ControlResponse, raw_json bool) {
	if raw_json {
		resp, err := json.Marshal(ret)
		if err != nil {
			fmt.Println("Error: Failed to print JSON")
		} else {
			fmt.Printf("%s\n", resp)
		}
	} else {
		fmt.Printf("Client got: %s\n", ret.ReturnCode)
		fmt.Printf("Data: %s\n", ret.Data)
	}
}
