package nscache

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	lru "github.com/hashicorp/golang-lru"
)

var (
	// This needs to be aligned with the maximum number of Pods we
	// expect in the system or more precisely the number of network
	// namespaces.
	netnsDefaultCacheSize = 256
	cache                 *lru.Cache
)

func init() {
	NewCache()
}

func NewCache() error {
	var err error

	if cache != nil {
		return nil
	}

	cache, err = lru.New(netnsDefaultCacheSize)
	return err
}

func GetPod(netns uint64) (*tetragon.Pod, error) {
	entry, ok := cache.Get(netns)
	if !ok {
		return nil, fmt.Errorf("no dns entry found")
	}
	return entry.(*tetragon.Pod), nil
}

func AddNetNs(netns uint64, pod *tetragon.Pod) {
	if _, ok := cache.Get(netns); ok {
		return
	}
	cache.Add(netns, pod)
}
