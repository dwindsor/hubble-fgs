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
	addr, _ := net.ResolveUnixAddr("unix", s.sockFile)
	dialer := net.Dialer{}

	for {
		s.conn, err = dialer.Dial("unix", addr.String())
		if err == nil {
			return nil
		}
		retries++
		if retries > MaxConnectRetry {
			return fmt.Errorf("datpaplane connect failed")
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
	s.cancel()
	return s.conn.Close()
}

func (s *DataplaneSocket) Send(msg *ControlMessage) error {
	err := s.encode.Encode(msg)
	if err != nil {
		return err
	}
	return nil
}

func (s *DataplaneSocket) Receive() (*ControlResponse, error) {
	var msg ControlResponse
	err := s.decode.Decode(&msg)
	if err != nil {
		return &ControlResponse{}, err
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
