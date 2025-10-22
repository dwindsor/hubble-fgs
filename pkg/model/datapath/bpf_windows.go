package datapath

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

const PATH_SIZE = 1024

func (p *BpfProgrammer) initMap() {
	var err error
	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		logger.GetLogger().Error(fmt.Sprintf("tcp preload collection is nil"))
	}
	dstMap := coll.Maps[destinationEndpointMap]
	if dstMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load destination endpoint map from collection"))
	}
	p.dstMap = NewTypedMap[types.DestinationEndpointKey, types.DestinationEndpointValue](dstMap)
	binaryMap := coll.Maps[processTreeBinaryUUIDMap]
	if binaryMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load process tree binary UID map from collection"))
	}
	p.binaryMap = NewTypedMap[processTreeBinaryUIDKey, processTreeID](binaryMap)

	uidBpfMap := coll.Maps[processTreeUUIDBinaryMap]
	if uidBpfMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load process tree UUID binary map from collection"))
	}
	p.uidBpfMap = NewTypedMap[processTreeID, processTreeBinaryUIDKey](uidBpfMap)

	p.lpmMap, err = lpm.NewLPM()
	if err != nil {
		logger.GetLogger().Warn("failed to create LPM programmer", logfields.Error, err)
	}
}

func scheduleDomainMapFlush() {

}
