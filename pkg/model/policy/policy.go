package policy

import (
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model"
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

// This is a somewhat lossy operation the BPF side may lose some stats during
// the update. However, this is a heavy operation to remove a quotas so we
// accept it.
func ClearDnsQuota() error {
	var dstVal model.DestinationEndpointValue
	var dstKey model.DestinationEndpointKey

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open destination endpoint map")
		return err
	}
	defer dstMap.Close()

	iter := dstMap.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		if dstVal.TxLimit == 0 {
			continue
		}

		dstVal.TxLimit = 0

		if err := dstMap.Update(dstKey, dstVal, 0); err != nil {
			return err
		}
	}
	return nil
}
