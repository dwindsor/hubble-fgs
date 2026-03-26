// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package file

import (
	"fmt"
	"slices"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors"
)

const (
	GlobPossibleMaxValues = 512 // this should match POSSIBLE_MAX_VALUES in bpf/file/bpf_glob.h

	BitmapShift = 6
	BitmapMask  = 63
	BitsPerByte = 8
)

type Bitmap struct {
	V [GlobPossibleMaxValues / BitsPerByte / unsafe.Sizeof(uint64(0))]uint64 // one bit per state
}

func (b *Bitmap) Set(n int) {
	word := n >> BitmapShift
	position := n & BitmapMask
	b.V[word] |= uint64(1) << uint64(position)
}

func GetAll(start *DFAState) (map[int32]map[int32]int32, map[int32][]int32) {
	visited := make(map[int]bool)
	queue := []*DFAState{start}
	visited[start.ID] = true

	isFinal := map[int32][]int32{}
	stateTransitions := map[int32]map[int32]int32{}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		t := map[int32]int32{}
		for char, next := range curr.Transitions {
			t[int32(char)] = int32(next.ID)
		}
		stateTransitions[int32(curr.ID)] = t

		// we need to deduplicate curr.Matches here
		// this array should be already sorted here
		isFinal[int32(curr.ID)] = slices.Compact(curr.Matches)

		for _, next := range curr.Transitions {
			if !visited[next.ID] {
				visited[next.ID] = true
				queue = append(queue, next)
			}
		}
	}

	return stateTransitions, isFinal
}

type GlobData struct {
	knownMap         map[int]bool              // tg_glob_literal
	finalStates      map[int32][]int32         // tg_glob_final
	stateTransitions map[int32]map[int32]int32 // tg_glob_dfa
}

func GenerateAndPopulateData(allPatterns map[string][]int32) GlobData {
	literals, knownMap := GetLiterals(allPatterns)
	nfa := BuildMultiNFA(allPatterns)
	dfa := ToDFA(nfa, literals)
	stateTransitions, finalStates := GetAll(dfa)

	return GlobData{
		knownMap:         knownMap,
		finalStates:      finalStates,
		stateTransitions: stateTransitions,
	}
}

func (g GlobData) GenerateKnownLiteralsMap(m *ebpf.Map) error {
	for c := range g.knownMap {
		one := uint8(1)
		if err := m.Update(int32(c), one, 0); err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
	}
	return nil
}

func (g GlobData) GetKnownLiteralsMapSize() int {
	if len(g.knownMap) > 0 {
		return len(g.knownMap)
	}
	return 1
}

func (g GlobData) GenerateFinalStatesMap(m *ebpf.Map) error {
	for c, f := range g.finalStates {
		if len(f) == 0 {
			continue
		}

		bitmap := Bitmap{}
		for _, b := range f {
			bitmap.Set(int(b))
		}

		if err := m.Update(c, bitmap, 0); err != nil {
			return fmt.Errorf("failed to insert bitmap: %w", err)
		}
	}
	return nil
}

func (g GlobData) GetFinalStatesMapSize() int {
	cnt := 0
	for _, f := range g.finalStates {
		if len(f) > 0 {
			cnt++
		}
	}
	if cnt == 0 {
		cnt++
	}
	return cnt
}

func (g GlobData) GenerateStateTransitionsMap(outerMap *ebpf.Map, pinPathPrefix string) error {
	generateInnerMap := func(i int32, s map[int32]int32) error {
		mapSize := uint32(len(s))
		if mapSize == 0 {
			mapSize = 1
		}

		innerName := fmt.Sprintf("tg_glob_dfa_%d", i)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: mapSize,
		}

		var innerMap *ebpf.Map
		var err error
		if pinPathPrefix == "" {
			innerMap, err = ebpf.NewMap(innerSpec)
		} else {
			innerMap, err = ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
				PinPath: sensors.PathJoin(pinPathPrefix, innerName),
			})
		}
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		for a, b := range s {
			if err := innerMap.Update(a, b, 0); err != nil {
				return fmt.Errorf("put failed: %w", err)
			}
		}

		if err := outerMap.Update(i, uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}

		return nil
	}

	for i, s := range g.stateTransitions {
		if err := generateInnerMap(i, s); err != nil {
			return fmt.Errorf("GenerateStateTransitionsMap: %w", err)
		}
	}
	return nil
}

func (g GlobData) GetStateTransitionsMapSize() int {
	if len(g.stateTransitions) > 0 {
		return len(g.stateTransitions)
	}
	return 1
}
