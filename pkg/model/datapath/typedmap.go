package datapath

import (
	"github.com/cilium/ebpf"
)

type mapInterfaceTyped[K any, V any] interface {
	Lookup(key K, result *V) error
	Update(key K, value V, flags ebpf.MapUpdateFlags) error
}

// Function that take two types and wraps *Map to a typed interface
func NewTypedMap[K any, V any](m *ebpf.Map) mapInterfaceTyped[K, V] {
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
