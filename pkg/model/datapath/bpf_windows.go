// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/ebpfmap"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

const PATH_SIZE = 1024

func (p *BPFProgrammer) initMap() {
	var err error
	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		logger.GetLogger().Error(fmt.Sprintf("tcp preload collection is nil"))
	}
	dstMap := coll.Maps[destinationEndpointMap]
	if dstMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load destination endpoint map from collection"))
	}

	binaryMap := coll.Maps[processTreeBinaryUUIDMap]
	if binaryMap == nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to load process tree binary UID map from collection"))
	}
	p.binaryMap = ebpfmap.NewTyped[processTreeBinaryUIDKey, processTreeID](binaryMap)

	lpmMap, err := lpm.NewLPM()
	if err != nil {
		logger.GetLogger().Warn("failed to create LPM programmer", logfields.Error, err)
	}

	p.recordBackend = &bpfRecordBackend{
		dstMap: ebpfmap.NewTyped[types.DestinationEndpointKey, types.DestinationEndpointValue](dstMap),
		lpmMap: lpmMap,
	}
}

func scheduleDomainMapFlush() {

}
