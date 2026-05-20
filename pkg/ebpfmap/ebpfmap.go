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
	"github.com/cilium/ebpf"
)

type Iterator interface {
	Next(keyOut, valueOut interface{}) bool
	Err() error
}

type InterfaceTyped[K any, V any] interface {
	Lookup(key K, result *V) error
	Update(key K, value V, flags ebpf.MapUpdateFlags) error
	Iterate() Iterator
	Delete(key K) error
}

// Function that take two types and wraps *Map to a typed interface
func NewTyped[K any, V any](m *ebpf.Map) InterfaceTyped[K, V] {
	return &ebpfMapTyped[K, V]{m: m}
}

type ebpfMapTyped[K any, V any] struct {
	m *ebpf.Map
}

func (em *ebpfMapTyped[K, V]) Lookup(key K, result *V) error {
	return em.m.Lookup(key, result)
}

func (em *ebpfMapTyped[K, V]) Update(key K, value V, flags ebpf.MapUpdateFlags) error {
	return em.m.Update(key, value, flags)
}

func (em *ebpfMapTyped[K, V]) Iterate() Iterator {
	return em.m.Iterate()
}

func (em *ebpfMapTyped[K, V]) Delete(key K) error {
	return em.m.Delete(key)
}
