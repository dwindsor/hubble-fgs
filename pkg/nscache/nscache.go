package nscache

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	lru "github.com/hashicorp/golang-lru/v2"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	cache *lru.Cache[uint64, *tetragon.Pod]
)

func init() {
	NewCache()
}

func NewCache() error {
	var err error

	if cache != nil {
		return nil
	}

	cache, err = lru.New[uint64, *tetragon.Pod](enterpriseOption.Config.NetNsCacheSize)
	return err
}

func ResizeCache(size int) error {
	if cache == nil {
		if err := NewCache(); err != nil {
			return err
		}
	}

	cache.Resize(size)
	return nil
}

func GetPod(netns uint64) (*tetragon.Pod, error) {
	entry, ok := cache.Get(netns)
	if !ok {
		return nil, fmt.Errorf("no pod entry found")
	}
	return entry, nil
}

func AddNetNs(netns uint64, pod *tetragon.Pod) {
	if _, ok := cache.Get(netns); ok {
		return
	}
	cache.Add(netns, pod)
}

func DelNetNs(netns uint64) {
	cache.Remove(netns)
}
