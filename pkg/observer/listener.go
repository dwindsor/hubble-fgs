//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package observer

import (
	"encoding/gob"
	"io"
	"net"
)

// Listener defines the interface to receive events from Observer. Listeners
// will merge and complete out-of-order events before they're passed to
// human-readable sinks such as the printer or GRPC encoder.
type Listener interface {
	// Notify gets called for each events from ObserverKprobe.
	Notify(msg interface{}) error

	// Close the listener.
	io.Closer
}

// ObserverChannel is a Listener that gob encodes events and sends them to a
// network connection.
type ObserverChannel struct {
	conn    net.Conn
	encoder *gob.Encoder
}

// NewObserverChannel initializes ObserverChannel.
func NewObserverChannel(conn net.Conn) *ObserverChannel {
	return &ObserverChannel{
		conn:    conn,
		encoder: gob.NewEncoder(conn),
	}
}

// Notify implements Listener.Notify.
func (o ObserverChannel) Notify(msg interface{}) error {
	return o.encoder.Encode(msg)
}

// Close implements Listener.Notify.
func (o ObserverChannel) Close() error {
	return o.conn.Close()
}
