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
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/ebpfmap"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

const PATH_SIZE = 256

func (p *BPFProgrammer) initMap() error {
	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		return fmt.Errorf("failed to load DestinationMap (%s): %w", file, err)
	}

	file = filepath.Join(bpf.MapPrefixPath(), processTreeBinaryUUIDMap)
	binaryMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		return fmt.Errorf("failed to load binary map (%s): %w", file, err)
	}
	p.binaryMap = ebpfmap.NewTyped[processTreeBinaryUIDKey, processTreeID](binaryMap)

	lpmMap, err := lpm.NewLPM()
	if err != nil {
		return fmt.Errorf("failed to create LPM programmer: %w", err)
	}

	p.recordBackend = &bpfRecordBackend{
		dstMap: ebpfmap.NewTyped[types.DestinationEndpointKey, types.DestinationEndpointValue](dstMap),
		lpmMap: lpmMap,
	}
	return nil
}

func scheduleDomainMapFlush() {
	var err error
	retries := 10

	for i := range retries {
		quotasDNSMappingsMu.Lock()
		for endpoint, id := range QuotasInitDNSDomainMappings {
			if err = dnsDomainMap.Update(endpoint.Dns, id); err != nil {
				break
			}
			// Successfully updated, remove from pending queue
			delete(QuotasInitDNSDomainMappings, endpoint)
		}
		quotasDNSMappingsMu.Unlock()
		if err == nil {
			return
		}
		logger.GetLogger().Debug("retry domain mapping", logfields.Error, err)
		time.Sleep(time.Duration(i) * time.Second)
	}
	logger.GetLogger().Warn("failed to program domain map policy incomplete")
}
