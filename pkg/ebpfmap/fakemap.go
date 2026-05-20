// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ebpfmap

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type KVPair[K any, V any] struct {
	a K
	b V
}

// fakeIterator implements Iterator for Fake maps
type fakeIterator[K fmt.Stringer, V any] struct {
	pairs []KVPair[K, V]
	idx   int
}

func (fi *fakeIterator[K, V]) Next(keyOut, valueOut interface{}) bool {
	if fi.idx >= len(fi.pairs) {
		return false
	}
	pair := fi.pairs[fi.idx]
	fi.idx++

	// Use type assertion to set the output values
	if kp, ok := keyOut.(*K); ok {
		*kp = pair.a
	}
	if vp, ok := valueOut.(*V); ok {
		*vp = pair.b
	}
	return true
}

func (fi *fakeIterator[K, V]) Err() error {
	return nil
}

// syncMap is a minimal generic wrapper over sync.Map, providing just the
// Load/Store/Delete/Iterate surface Fake needs. It lets us avoid depending on
// github.com/cilium/cilium/pkg/lock for a single in-memory test helper.
type syncMap[K comparable, V any] struct {
	m sync.Map
}

func (sm *syncMap[K, V]) Load(key K) (V, bool) {
	v, ok := sm.m.Load(key)
	if !ok {
		var zero V
		return zero, false
	}
	return v.(V), true
}

func (sm *syncMap[K, V]) Store(key K, value V) {
	sm.m.Store(key, value)
}

func (sm *syncMap[K, V]) Delete(key K) {
	sm.m.Delete(key)
}

func (sm *syncMap[K, V]) Range(f func(key K, value V) bool) {
	sm.m.Range(func(k, v any) bool {
		return f(k.(K), v.(V))
	})
}

type Fake[K fmt.Stringer, V any] struct {
	syncMap[string, KVPair[K, V]]
}

func (fm *Fake[K, V]) Lookup(key K, result *V) error {
	v, exists := fm.Load(key.String())
	if !exists {
		return ebpf.ErrKeyNotExist
	}
	*result = v.b
	return nil
}

func (fm *Fake[K, V]) Update(key K, value V, _ ebpf.MapUpdateFlags) error {
	fm.Store(key.String(), KVPair[K, V]{a: key, b: value})
	return nil
}

func (fm *Fake[K, V]) Delete(key K) error {
	fm.syncMap.Delete(key.String())
	return nil
}

func (fm *Fake[K, V]) Iterate() Iterator {
	var pairs []KVPair[K, V]
	fm.Range(func(_ string, v KVPair[K, V]) bool {
		pairs = append(pairs, v)
		return true
	})
	return &fakeIterator[K, V]{pairs: pairs}
}
