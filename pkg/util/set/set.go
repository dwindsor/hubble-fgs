// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package set provides a minimal generic set type used within hubble-fgs.
// It covers only the API surface consumed by our packages so we do not need
// to depend on github.com/cilium/cilium/pkg/container/set.
package set

// Set is an unordered collection of comparable elements.
type Set[T comparable] map[T]struct{}

// NewSet returns a new empty set.
func NewSet[T comparable]() Set[T] {
	return Set[T]{}
}

// Has reports whether member is present in the set.
func (s Set[T]) Has(member T) bool {
	_, ok := s[member]
	return ok
}

// Insert adds member to the set. It returns true if the set was modified.
func (s Set[T]) Insert(member T) bool {
	if _, ok := s[member]; ok {
		return false
	}
	s[member] = struct{}{}
	return true
}

// AsSlice returns the set members as a slice in unspecified order.
func (s Set[T]) AsSlice() []T {
	out := make([]T, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}
