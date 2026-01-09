// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exporter

import (
	"context"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// Constant values
const (
	TIMEOUT     = 30 // Timeout in seconds for starting services
	UDS_TIMEOUT = 5  // Timeout in seconds for UDS connection

	EXPORTER_PORT_COUNT = 8 // Amount of ports dedicated to log export
)

// Dataplane types
type ExporterType string

const (
	ACCELERATED_FLUENTBIT_EXPORTER ExporterType = "accelerated-fluentbit"
	MOCK_EXPORTER                  ExporterType = "mock"
)

// Exporter Interface
type Exporter interface {
	// Attributes
	Mode() ExporterType
	Version() string

	// Configuration
	RefreshConfig(*v1alpha.ConfigObject, *v1alpha.ConfigObject) error

	// Management
	Init(context.Context) error
	Connect(context.Context, bool) error
	Close(context.Context)
	Start(context.Context) error
	Stop(context.Context) error
	Restart(context.Context) error
	Status() bool
}
