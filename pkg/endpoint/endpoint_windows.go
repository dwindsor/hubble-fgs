package endpoint

import (
	"errors"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
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
	revLru, err := lru.New[Endpoint, uint64](option.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}

	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		return nil, errors.New("tcp preload collection is nil")
	}
	m := coll.Maps[endpointIdMap]
	if m == nil {
		return nil, errors.New("failed to load endpoint id map from collection")
	}

	cache = &Cache{
		cache:       fwdlru,
		revCache:    revLru,
		endpointMap: m,
	}

	return cache, nil
}
