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

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/ebpf"
)

type KVPair[K any, V any] struct {
	a K
	b V
}

type Fake[K fmt.Stringer, V any] struct {
	lock.Map[string, KVPair[K, V]]
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
	fm.Map.Delete(key.String())
	return nil
}

func (fm *Fake[K, V]) Iterate() *ebpf.MapIterator {
	return nil
}
