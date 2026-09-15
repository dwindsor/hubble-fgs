// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package endpoint

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

func newCache() (EndpointCache, error) {
	if cache != nil {
		return cache, nil
	}

	logger.GetLogger().Info("Initializing Endpoint cache", "size", option.Config.EndpointCacheSize)
	fwdlru, err := lru.New[uint64, Endpoint](option.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}
	revLru, err := lru.New[endpointIdentity, uint64](option.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}

	spec := &ebpf.MapSpec{
		Name:       endpointIdMap,
		Type:       bpf.BPF_MAP_TYPE_LRU_HASH,
		KeySize:    uint32(unsafe.Sizeof(endpointKey{})),
		ValueSize:  uint32(unsafe.Sizeof(endpointValue{})),
		MaxEntries: uint32(option.Config.EndpointCacheSize),
		Pinning:    ebpf.PinByName,
	}
	opts := ebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}
	m, err := ebpf.NewMapWithOptions(spec, opts)
	if err != nil {
		logger.GetLogger().Warn("Could not create endpoint map", logfields.Error, err)
		return nil, err
	}

	cache = &Cache{
		cache:       fwdlru,
		revCache:    revLru,
		endpointMap: m,
	}

	return cache, nil
}
