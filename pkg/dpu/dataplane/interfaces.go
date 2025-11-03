package dataplane

import (
	"context"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	dpuPolicy "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
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

// Dataplane Interface
type Dataplane interface {
	// Attributes
	Type() DataplaneType
	Version() string
	ApiPath() string

	// Commands
	PushPolicy(context.Context, v1alpha.PolicyOperation, []*dpuPolicy.DPUPolicyRule) error
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

type DataplaneDpuConfig struct {
	NpuIP  string `json:"service_ip"`
	NpuMAC string `json:"service_mac"`
}

type LogCollector struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
