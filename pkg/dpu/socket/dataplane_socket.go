package socket

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
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

func (s *DataplaneSocket) Connect() error {
	// Resolving the socket address
	addr, _ := net.ResolveUnixAddr("unix", s.sockFile)
	dialer := net.Dialer{}
	conn, err := dialer.Dial("unix", addr.String())
	if err != nil {
		return err
	}
	s.conn = conn

	// Setting timeout for the connection
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	s.cancel = cancel
	deadline, _ := ctxWithTimeout.Deadline()
	s.conn.SetDeadline(deadline)

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
