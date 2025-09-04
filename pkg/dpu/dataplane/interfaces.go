package dataplane

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	dpuPolicy "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

// Constant values
const (
	TIMEOUT     = 30 // Timeout in seconds for starting services
	UDS_TIMEOUT = 5  // Timeout in seconds for UDS connection
)

// Dataplane types
type DataplaneType string

const (
	ACCELERATED DataplaneType = "accelerated"
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
