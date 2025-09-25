package dataplane

import (
	"context"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/dpu/policy"
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
	ACCELERATED DataplaneType = "accelerated"
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
)

// Policy command values
const (
	UpdatePolicy int = iota
	RemovePolicy
	ListPolicies
)

// Local file paths for dataplane and dispatcher
var (
	DATAPLANE_SERVICE = "daf-dp"
	BINARY_DIR        = "/opt/cisco/daf/bin"
	DATAPLANE_DIR     = "/opt/cisco/daf/bin/dp"
	DATAPLANE_BINARY  = "/usr/bin/vpp"
	CONFIGURE_SCRIPT  = "/bin/configure_dp.sh"
	TEMP_DIR          = "/tmp/daf"
	FIFODIR           = "crash"
)

// Dataplane Interface
type Dataplane interface {
	// Attributes
	Mode() DataplaneType
	Version() string
	ApiPath() string
	PolicyList() []policy.FwPolicyV2

	// Commands
	PushPolicy(context.Context, []*dpuPolicy.DPUPolicyRule) error
	RemovePolicy(context.Context) error

	// Configuration
	RefreshConfig(*v1alpha.ConfigObject, *v1alpha.ConfigObject) error

	// Management
	Init(context.Context, string, string) error
	Connect(context.Context, string, bool) error
	Close(context.Context)
	Start(context.Context) error
	Stop(context.Context) error
	Restart(context.Context) error
	Status() bool // TODO: Needed?
}

// Policy File Object
type PolicyFile struct {
	PolicyList []policy.FwPolicyV2 `json:"policy_list"`
}

// Dataplane Log Configuration Object
type LogConfig struct {
	LogEnabled     bool           `json:"log_enabled"`
	UnixPath       string         `json:"unix_path,omitempty"`
	DataplaneLevel interface{}    `json:"dataplane_level,omitempty"`
	NpuIP          string         `json:"npu_ip,omitempty"`
	NpuMAC         string         `json:"npu_mac,omitempty"`
	Collector      []LogCollector `json:"collector"`
}

type LogCollector struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
