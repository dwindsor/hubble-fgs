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
	"regexp"
	"strings"
	"unicode/utf8"
	"unsafe"
)

const (
	GlobPossibleMaxStates = 512 // this should match POSSIBLE_MAX_STATES in bpf/file/bpf_glob.h
	BitsPerByte           = 8
)

type GlobTempVal struct {
	V      [GlobPossibleMaxStates / BitsPerByte / unsafe.Sizeof(uint64(0))]uint64 // one bit per state
	Values [GlobPossibleMaxStates]uint32
	Cnt    uint64
}

type GlobState struct {
	idx       int32   `align:"idx"`       // my ID (i.e. index in the state array)
	nextChar  int32   `align:"nextChar"`  // valid only when hasChar == true
	nextStar  int32   `align:"nextStar"`  // valid only when hasStar == true
	nextQmark int32   `align:"nextQmark"` // valid only when hasQmark == true
	hasChar   bool    `align:"hasChar"`   // char transition
	hasStar   bool    `align:"hasStar"`   // * transition
	hasQmark  bool    `align:"hasQmark"`  // ? transition
	isFinal   bool    `align:"isFinal"`
	valueChar byte    `align:"valueChar"` // valid only when hasChar == true
	_         [3]byte `align:"pad"`
}

func (s *GlobState) AddTransition(input rune, target int32) {
	switch input {
	case '*':
		s.hasStar = true
		s.nextStar = target
	case '?':
		s.hasQmark = true
		s.nextQmark = target
	default:
		s.hasChar = true
		s.valueChar = byte(input)
		s.nextChar = target
	}
}

func (s *GlobState) GetNextStates(input rune) []int32 {
	nextStates := []int32{}
	if s.hasChar && s.valueChar == byte(input) {
		nextStates = append(nextStates, s.nextChar)
	}
	if s.hasQmark {
		nextStates = append(nextStates, s.nextQmark)
	}
	if s.hasStar {
		nextStates = append(nextStates, s.nextStar)
		nextStates = append(nextStates, s.idx)
	}
	return nextStates
}

type GlobFSM struct {
	stateIdx int32
	stateArr []GlobState
}

func (f *GlobFSM) GetStates() []GlobState {
	return f.stateArr
}

func (f *GlobFSM) NewState(isFinal bool) int32 {
	f.stateArr = append(f.stateArr, GlobState{
		idx:       f.stateIdx,
		hasChar:   false,
		valueChar: 0,
		nextChar:  0,
		hasStar:   false,
		nextStar:  0,
		isFinal:   isFinal,
	})
	oldStateIdx := f.stateIdx
	f.stateIdx++
	return oldStateIdx
}

func (f *GlobFSM) Print() {
	for _, s := range f.stateArr {
		if s.hasChar {
			fmt.Println("state:", s.idx, "rune:", string(s.valueChar), "next:", s.nextChar, "final:", s.isFinal)
		}
		if s.hasStar {
			fmt.Println("state:", s.idx, "rune:", "*", "next:", s.nextStar, "final:", s.isFinal)
		}
		if s.hasQmark {
			fmt.Println("state:", s.idx, "rune:", "?", "next:", s.nextStar, "final:", s.isFinal)
		}
	}
}

func CompileGlob(pattern string) (*GlobFSM, error) {
	if regexp.MustCompile(`\s`).MatchString(pattern) {
		return nil, fmt.Errorf("compileGlob: pattern cannot contain any whitespace. pattern:[%s]", pattern)
	}

	if strings.Contains(pattern, "**") {
		return nil, fmt.Errorf("compileGlob: pattern cannot contain a globstar (i.e. **). pattern:[%s]", pattern)
	}

	for _, c := range pattern {
		if utf8.RuneLen(c) != 1 {
			return nil, fmt.Errorf("compileGlob: pattern cannot contain any invalid characters (i.e. need more than one bytes to represent). pattern:[%s] invalid:[%s]", pattern, string(c))
		}

		if c == '[' || c == ']' || c == '{' || c == '}' {
			return nil, fmt.Errorf("compileGlob: pattern cannot contain any if these characters '[]{}'. pattern:[%s]", pattern)
		}
	}

	fsm := &GlobFSM{
		stateIdx: 0,
		stateArr: []GlobState{},
	}

	currentState := fsm.NewState(false)
	for i, char := range pattern {
		// each character in the patter should require a single byte to be represented
		if utf8.RuneLen(char) != 1 {
			panic("rune requires more than one bytes")
		}

		final := i == len(pattern)-1
		nextState := fsm.NewState(final)
		switch char {
		case '*':
			if final {
				// last char in pattern is '*' so make the currentState final as well
				fsm.stateArr[currentState].isFinal = true
			}
			fsm.stateArr[currentState].AddTransition('*', nextState)
			fsm.stateArr[nextState].AddTransition('*', nextState)
		default:
			// match a specific or any (?) character.
			// previous is '*' so add a transition from previous-1 to this state
			if fsm.stateArr[currentState].hasStar && currentState > 0 {
				fsm.stateArr[currentState-1].AddTransition(char, nextState)
			}
			fsm.stateArr[currentState].AddTransition(char, nextState)
		}
		currentState = nextState
	}

	return fsm, nil
}

func (f *GlobFSM) Match(str string) bool {
	currentStates := map[int32]bool{0: true}

	for _, char := range str {
		nextStatesSet := make(map[int32]bool)

		for state := range currentStates {
			for _, ss := range f.stateArr[state].GetNextStates(char) {
				nextStatesSet[ss] = true
			}
		}

		currentStates = nextStatesSet
		if len(currentStates) == 0 {
			return false
		}
	}

	for state := range currentStates {
		if f.stateArr[state].isFinal {
			return true
		}
	}

	return false
}
