// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nscache

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/api/v1/tetragon"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type nscacheData struct {
	Pod   *tetragon.Pod
	Pid   uint32
	Netns uint64
}

var (
	cache *lru.Cache[uint64, *nscacheData]
)

func init() {
	NewCache()
}

func NewCache() error {
	var err error

	if cache != nil {
		return nil
	}

	cache, err = lru.New[uint64, *nscacheData](enterpriseOption.Config.NetNsCacheSize)
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
	return entry.Pod, nil
}

func AddNetNs(netns uint64, pod *tetragon.Pod, pid uint32) {
	if _, ok := cache.Get(netns); ok {
		return
	}

	data := &nscacheData{
		Pod:   pod,
		Pid:   pid,
		Netns: netns,
	}
	cache.Add(netns, data)
}

func DelNetNs(netns uint64) {
	cache.Remove(netns)
}

func GetCache() *lru.Cache[uint64, *nscacheData] {
	return cache
}
