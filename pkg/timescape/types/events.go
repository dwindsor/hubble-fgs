// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	systemstatus "github.com/isovalent/ipa/system_status/v1alpha"
)

// Priority represents the processing priority of messages
type Priority int

const (
	PriorityHigh Priority = iota
	PriorityLow
)

// String returns a string representation of the priority for logging
func (p Priority) String() string {
	switch p {
	case PriorityHigh:
		return "HIGH"
	case PriorityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// ErrorCode represents structured error codes for timescape operations
type ErrorCode int

const (
	ErrCodeSuccess      ErrorCode = 0
	ErrCodeFailure      ErrorCode = 1
	ErrCodeQueueBusy    ErrorCode = 2
	ErrCodeShuttingDown ErrorCode = 3
)

// Msg represents a message in the queue with metadata
type Msg struct {
	ID       string                          // traceable ID (uuid)
	Priority Priority                        // routing priority
	Event    *systemstatus.SystemStatusEvent // protobuf message
}
