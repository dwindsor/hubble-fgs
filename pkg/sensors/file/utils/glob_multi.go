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
	"sort"
	"strings"
)

const (
	TypeEpsilon = iota
	TypeLiteral
	TypeAny   // ?
	TypeClass // [abc] or [!abc]
)

// Helper for "Other" transitions in DFA
const Other = -999

type State struct {
	ID       int
	Type     int
	Char     rune
	Class    map[rune]bool
	NotClass bool
	Out      *State
	Out1     *State
	MatchID  []int32
}

type NFA struct {
	Start *State
}

type DFAState struct {
	ID          int
	Transitions map[int]*DFAState
	Matches     []int32
}

// --- Parser ---
type parserCtx struct {
	pattern string
	pos     int
}

func (p *parserCtx) current() rune {
	if p.pos >= len(p.pattern) {
		return 0
	}
	return rune(p.pattern[p.pos])
}

func (p *parserCtx) advance() { p.pos++ }

func buildFrag(ctx *parserCtx) (*State, *State) {
	start := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
	end := start

	for ctx.pos < len(ctx.pattern) {
		char := ctx.current()

		if char == '}' || char == ',' {
			break
		}

		newState := &State{MatchID: []int32{-1}}

		switch char {
		case '?':
			newState.Type = TypeAny
			end.Out = newState
			end = newState
			ctx.advance()

		case '*':
			hub := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			end.Out = hub
			loopStep := &State{Type: TypeAny, MatchID: []int32{-1}}
			hub.Out = loopStep
			loopStep.Out = hub
			hub.Out1 = newState
			end = newState
			ctx.advance()

		case '[':
			ctx.advance()
			negate := false
			if ctx.current() == '!' {
				negate = true
				ctx.advance()
			}

			charSet := make(map[rune]bool)
			var prevChar rune = -1 // Track previous char for range detection

			for ctx.pos < len(ctx.pattern) && ctx.current() != ']' {
				curr := ctx.current()

				// Check for Range: we see a hyphen, we have a previous char,
				// and the NEXT char is not the closing bracket.
				isRange := false
				if curr == '-' && prevChar != -1 {
					// Peek ahead
					nextPos := ctx.pos + 1
					if nextPos < len(ctx.pattern) && rune(ctx.pattern[nextPos]) != ']' {
						isRange = true
						ctx.advance() // Consume '-'
						rangeEnd := ctx.current()

						// Add all characters in range
						for r := prevChar + 1; r <= rangeEnd; r++ {
							charSet[r] = true
						}
						// The 'rangeEnd' itself will be added by the standard logic below
						// or we can consume it here. Let's consume it here to allow "a-c-e" logic if needed,
						// but simpler is to set curr = rangeEnd and let loop finish.
						curr = rangeEnd
						prevChar = -1 // Reset prev so we don't chain ranges incorrectly immediately
					}
				}

				if !isRange {
					charSet[curr] = true
					prevChar = curr
				}
				ctx.advance()
			}
			if ctx.current() == ']' {
				ctx.advance()
			}

			newState.Type = TypeClass
			newState.Class = charSet
			newState.NotClass = negate
			end.Out = newState
			end = newState

		case '{':
			ctx.advance()
			splitStart := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			splitEnd := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			end.Out = splitStart

			for {
				subStart, subEnd := buildFrag(ctx)
				if splitStart.Out == nil {
					splitStart.Out = subStart
				} else if splitStart.Out1 == nil {
					splitStart.Out1 = subStart
				} else {
					newSplit := &State{Type: TypeEpsilon, Out: subStart, Out1: splitStart.Out1, MatchID: []int32{-1}}
					splitStart.Out1 = newSplit
				}
				subEnd.Out = splitEnd

				if ctx.current() == '}' {
					ctx.advance()
					break
				} else if ctx.current() == ',' {
					ctx.advance()
				} else {
					break
				}
			}
			end = splitEnd

		default:
			newState.Type = TypeLiteral
			newState.Char = char
			end.Out = newState
			end = newState
			ctx.advance()
		}
	}
	return start, end
}

func buildPatternNFA(pattern string, id []int32) (*State, *State) {
	ctx := &parserCtx{pattern: pattern, pos: 0}
	start, end := buildFrag(ctx)
	// Create explicit success state
	success := &State{Type: TypeEpsilon, MatchID: id}
	end.Out = success
	return start, success
}

func BuildMultiNFA(patterns map[string][]int32) *NFA {
	globalStart := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
	curr := globalStart
	idx := 0
	for p, i := range patterns {
		pStart, _ := buildPatternNFA(p, i)
		curr.Out = pStart
		if idx < len(patterns)-1 {
			next := &State{Type: TypeEpsilon, MatchID: []int32{-1}}
			curr.Out1 = next
			curr = next
		}
		idx++
	}
	assignIDs(globalStart)
	return &NFA{Start: globalStart}
}

func matches(s *State, char int) bool {
	r := rune(char)
	switch s.Type {
	case TypeLiteral:
		return s.Char == r
	case TypeAny:
		return true
	case TypeClass:
		_, found := s.Class[r]
		if s.NotClass {
			return !found
		}
		return found
	}
	return false
}

func GetLiterals(patterns map[string][]int32) ([]int, map[int]bool) {
	seen := make(map[rune]bool)
	literals := []int{}
	knownMap := make(map[int]bool)

	add := func(r rune) {
		if !seen[r] {
			seen[r] = true
			literals = append(literals, int(r))
			knownMap[int(r)] = true
		}
	}

	for p := range patterns {
		var prevChar rune = -1
		inBracket := false

		for i := 0; i < len(p); i++ {
			c := rune(p[i])

			if c == '[' {
				inBracket = true
				prevChar = -1
				continue
			}
			if c == ']' {
				inBracket = false
				prevChar = -1
				continue
			}

			if inBracket {
				// Handle negation '!' skipping
				if c == '!' && i > 0 && p[i-1] == '[' {
					continue
				}

				// Check for Range Detection similar to Parser
				if c == '-' && prevChar != -1 {
					// Check lookahead
					if i+1 < len(p) && p[i+1] != ']' {
						rangeEnd := rune(p[i+1])
						// Expand range
						for k := prevChar + 1; k < rangeEnd; k++ {
							add(k)
						}
						// We don't add '-' as a literal here if it's acting as an operator
						continue
					}
				}
				add(c)
				prevChar = c
			} else {
				// Outside brackets
				if !strings.ContainsRune("*?{},", c) {
					add(c)
				}
			}
		}
	}
	return literals, knownMap
}

func ToDFA(nfa *NFA, literals []int) *DFAState {
	alphabet := append(literals, Other)

	startClosure := epsilonClosure([]*State{nfa.Start})
	startDFA := &DFAState{ID: 0, Transitions: make(map[int]*DFAState)}
	startDFA.Matches = getMatches(startClosure)

	knownStates := map[string]*DFAState{stateSetKey(startClosure): startDFA}
	queue := []*DFAState{startDFA}
	stateSets := map[int][]*State{0: startClosure}
	idCounter := 1

	for len(queue) > 0 {
		currDFA := queue[0]
		queue = queue[1:]
		currNFAStates := stateSets[currDFA.ID]

		for _, inputChar := range alphabet {
			moveSet := []*State{}

			for _, s := range currNFAStates {
				isMatch := false
				if inputChar == Other {
					// Other matches if the state accepts things NOT in our literal list
					if s.Type == TypeAny {
						isMatch = true
					} else if s.Type == TypeClass && s.NotClass {
						isMatch = true
					}
				} else {
					isMatch = matches(s, inputChar)
				}

				if isMatch {
					if s.Out != nil {
						moveSet = append(moveSet, s.Out)
					}
					if s.Out1 != nil {
						moveSet = append(moveSet, s.Out1)
					}
				}
			}

			if len(moveSet) == 0 {
				continue
			}

			closure := epsilonClosure(moveSet)
			key := stateSetKey(closure)

			if target, exists := knownStates[key]; exists {
				currDFA.Transitions[inputChar] = target
			} else {
				newDFA := &DFAState{ID: idCounter, Transitions: make(map[int]*DFAState)}
				idCounter++
				newDFA.Matches = getMatches(closure)

				knownStates[key] = newDFA
				stateSets[newDFA.ID] = closure
				currDFA.Transitions[inputChar] = newDFA
				queue = append(queue, newDFA)
			}
		}
	}
	return startDFA
}

func assignIDs(start *State) {
	visited := make(map[*State]bool)
	id := 0
	var dfs func(*State)
	dfs = func(s *State) {
		if s == nil || visited[s] {
			return
		}
		visited[s] = true
		s.ID = id
		id++
		dfs(s.Out)
		dfs(s.Out1)
	}
	dfs(start)
}

func epsilonClosure(states []*State) []*State {
	stack := append([]*State{}, states...)
	closure := make(map[int]*State)
	for _, s := range states {
		closure[s.ID] = s
	}

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if s.Type == TypeEpsilon {
			targets := []*State{s.Out, s.Out1}
			for _, t := range targets {
				if t != nil {
					if _, exists := closure[t.ID]; !exists {
						closure[t.ID] = t
						stack = append(stack, t)
					}
				}
			}
		}
	}
	res := []*State{}
	for _, s := range closure {
		res = append(res, s)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res
}

func getMatches(states []*State) []int32 {
	matches := []int32{}
	seen := make(map[int32]bool)
	for _, s := range states {
		for _, matchID := range s.MatchID {
			if matchID != -1 && !seen[matchID] {
				matches = append(matches, matchID)
				seen[matchID] = true
			}
		}
	}
	slices.Sort(matches)
	return matches
}

func stateSetKey(states []*State) string {
	ids := []string{}
	for _, s := range states {
		ids = append(ids, fmt.Sprintf("%d", s.ID))
	}
	return strings.Join(ids, ",")
}

func MatchString(dfa *DFAState, input string, knownLiterals map[int]bool) []int32 {
	current := dfa
	for _, char := range input {
		c := int(char)

		// 1. Try Specific Transition
		next, exists := current.Transitions[c]

		if !exists {
			// 2. If NOT exists, we check if this char is "Known"
			if knownLiterals[c] {
				// It IS a known literal (like 'b' in [!b]), but had no transition.
				// This means it failed the check. We must NOT use "Other".
				return nil
			}

			// 3. If it is Unknown (like 'z'), use Other fallback
			next, exists = current.Transitions[Other]
		}

		if !exists {
			return nil
		}
		current = next
	}
	return current.Matches
}
