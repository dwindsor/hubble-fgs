package socket

import (
	"encoding/json"
	"fmt"
)

// ControlSocket defines the interface for communicating with the dataplane.
// The values below are defined according to the API specification (bottom of
// the page) defined in confluence.
// https://confluence-eng-rtp2.cisco.com/conf/display/PROG/Dual+Dataplane+and+Packet+Dispatcher+Design

type ControlSocket interface {
	Connect() error
	Close() error
	Send(ControlMessage) error
	Receive() (ControlResponse, error)
}

type ControlMessage struct {
	Command int             `json:"command"`
	Type    CommandType     `json:"type"`
	Data    json.RawMessage `json:"data"`
}

type CommandType int

const (
	DISPATCHER CommandType = iota
	DATAPLANE
	POLICY
)

type ControlResponse struct {
	ReturnCode ErrorCode       `json:"code"`
	Data       json.RawMessage `json:"data"`
}

type ErrorCode int

const (
	ERROR_INVALID_STATE ErrorCode = iota - 3
	ERROR_OOM
	ERROR
	SUCCESS
	UNKNOWN
	NOT_SUPPORTED
)

func (e ErrorCode) String() string {
	switch e {
	case ERROR_INVALID_STATE:
		return "Error: Invalid state"
	case ERROR_OOM:
		return "Error: Out of memory"
	case ERROR:
		return "Error"
	case SUCCESS:
		return "Success"
	case UNKNOWN:
		return "Unknown"
	case NOT_SUPPORTED:
		return "Not supported"
	default:
		return fmt.Sprintf("%d", int(e))
	}
}
