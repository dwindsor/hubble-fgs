package datapath

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

func initMap() {
	var err error
	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		logger.GetLogger().Error(fmt.Sprintf("tcp preload collection is nil"))
	}
	dstMap = coll.Maps[destinationEndpointMap]
	if dstMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load destination endpoint map from collection"))
	}

	lpmMap, err = lpm.NewLPM()
	if err != nil {
		logger.GetLogger().Warn("failed to create LPM programmer", logfields.Error, err)
	}
}

func scheduleDomainMapFlush() {

}
