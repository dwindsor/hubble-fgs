package policy

import (
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func AddUnsafeNetworkPolicy(_ string, _ *types.TetragonNetworkPolicy) error {
	logger.GetLogger().Warn("Unsupported qos tracing policy")
	return nil
}

// This is a somewhat lossy operation the BPF side may lose some stats during
// the update. However, this is a heavy operation to remove a quotas so we
// accept it.
func ClearDnsPolicy(_ string, _ *types.TetragonNetworkPolicy) error {
	logger.GetLogger().Warn("Unsupported qos tracing policy")
	return nil
}
