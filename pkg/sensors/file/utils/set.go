// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux

package file

import "fmt"

type Set[E comparable] map[E]struct{}

func NewSet[E comparable](vals ...E) Set[E] {
	s := Set[E]{}
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

func (s Set[E]) Add(vals ...E) {
	for _, v := range vals {
		s[v] = struct{}{}
	}
}

func (s Set[E]) Contains(v E) bool {
	_, ok := s[v]
	return ok
}

func (s Set[E]) Members() []E {
	result := make([]E, 0, len(s))
	for v := range s {
		result = append(result, v)
	}
	return result
}

func (s Set[E]) String() string {
	return fmt.Sprintf("%v", s.Members())
}

func (s Set[E]) Union(s2 Set[E]) Set[E] {
	result := NewSet(s.Members()...)
	result.Add(s2.Members()...)
	return result
}

func (s Set[E]) Intersection(s2 Set[E]) Set[E] {
	result := NewSet[E]()
	for _, v := range s.Members() {
		if s2.Contains(v) {
			result.Add(v)
		}
	}
	return result
}

func (s Set[E]) Difference(s2 Set[E]) Set[E] {
	result := NewSet[E]()
	for _, v := range s.Members() {
		if !s2.Contains(v) {
			result.Add(v)
		}
	}
	return result
}
