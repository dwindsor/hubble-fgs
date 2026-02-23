// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package events

import (
	"time"

	"github.com/isovalent/hubble-fgs/pkg/logexport/unixjson"
)

// NewEventLogger creates a new EventLogger instance
func NewEventLogger(socketPath string) *EventLogger {
	return &EventLogger{
		socketPath: socketPath,
		client:     unixjson.NewClient(socketPath),
	}
}

// EventLogger represents a logger that writes to a Unix domain socket using UDP
type EventLogger struct {
	socketPath string
	client     *unixjson.Client
}

// Connect establishes a connection to the Unix socket and locks the mutex
func (s *EventLogger) Connect() error {
	return s.client.Connect()
}

// Close closes the connection to the Unix socket
func (s *EventLogger) Close() error {
	return s.client.Close()
}

// Log writes a message to the Unix socket, connecting if necessary
func (s *EventLogger) Log(message EventLogMessage) error {
	message.Timebuf = time.Now().Format("2006-01-02T15:04:05.000Z")
	return s.client.Write(message)
}

// IsConnected returns whether the eventlogger is currently connected
func (s *EventLogger) IsConnected() bool {
	return s.client.IsConnected()
}
