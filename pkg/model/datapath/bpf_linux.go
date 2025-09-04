package datapath

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

func (p *BpfProgrammer) initMap() {
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin DestinationMap (%s): %v", file, err))
	}
	p.dstMap = NewTypedMap[types.DestinationEndpointKey, types.DestinationEndpointValue](dstMap)

	file = filepath.Join(bpf.MapPrefixPath(), processTreeBinaryUUIDMap)
	binaryMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Warn("failed to open file", "file", file, logfields.Error, err)
	}
	p.binaryMap = NewTypedMap[processTreeBinaryUIDKey, processTreeID](binaryMap)

	file = filepath.Join(bpf.MapPrefixPath(), processTreeUUIDBinaryMap)
	uidBpfMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Warn("failed to open file", "file", file, logfields.Error, err)
	}
	p.uidBpfMap = NewTypedMap[processTreeID, processTreeBinaryUIDKey](uidBpfMap)

	p.lpmMap, err = lpm.NewLPM()
	if err != nil {
		logger.GetLogger().Warn("failed to create LPM programmer", logfields.Error, err)
	}
}

func scheduleDomainMapFlush() {
	var err error
	retries := 10

	for i := 0; i < retries; i++ {
		for endpoint, id := range QuotasInitDNSDomainMappings {
			if err = dnsDomainMap.Update(endpoint.Dns, id); err != nil {
				break
			}
		}
		if err == nil {
			return
		}
		logger.GetLogger().Debug("retry domain mapping", logfields.Error, err)
		time.Sleep(time.Duration(i) * time.Second)
	}
	logger.GetLogger().Warn("failed to program domain map policy incomplete")
}
