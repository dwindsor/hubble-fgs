// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dataplane

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// Constant values
const (
	TIMEOUT            = 30     // Timeout in seconds for starting services
	UDS_TIMEOUT        = 5      // Timeout in seconds for UDS connection
	LOGGER_PORT_COUNT  = 8      // Ports reserved for log exporter
	EXPORTER_INTERFACE = "dsc0" // Name of the interface used for export packets
)

// Dataplane types
type DataplaneType string

const (
	ACCELERATED_DP DataplaneType = "accelerated"
	MOCK_DP        DataplaneType = "mock"
)

// Dataplane command values
const (
	Dataplane_Role int = iota
	Dataplane_Policies
	Dataplane_Process
	Dataplane_Hash
	Dataplane_Flows
	Dataplane_Snapshot
	Dataplane_UpdatePolicies
	Dataplane_RemovePolicies
	Dataplane_ListPolicies
	Dataplane_LogConfig
	Dataplane_DpuConfig = 20
)

// Policy command values
const (
	UpdatePolicy = 0
	RemovePolicy = 1
	ListPolicies = 2
	ClearPolicy  = 4
)

// DPU Board ID to Asic type mappings
var (
	dpuBoardMap = map[string]string{
		"0x02820001": "elba",
		"0x03610001": "giglio",
		"0x03620001": "giglio",
	}
)

// Dataplane Interface
type Dataplane interface {
	// Attributes
	Type() DataplaneType
	Version() string
	ApiPath() string
	HardwareModel() string

	// Commands
	PushPolicy(context.Context, v1alpha.PolicyOperation, []*switchpolicy.DPUPolicyRule) error
	ClearPolicy(context.Context) error

	// Configuration
	RefreshConfig(*v1alpha.ConfigObject, *v1alpha.ConfigObject) error

	// Management
	Init(context.Context) error
	Connect(context.Context) error
	Close(context.Context)
	Start(context.Context) error
	Stop(context.Context) error
	Restart(context.Context) error
	Status() bool
}

// Dataplane Log Configuration Object
type LogConfig struct {
	LogEnabled     bool           `json:"log_enabled"`
	UnixPath       string         `json:"unix_path,omitempty"`
	DataplaneLevel interface{}    `json:"dataplane_level,omitempty"`
	Collector      []LogCollector `json:"collector"`
}

type LogCollector struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
