// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"errors"
	"path/filepath"
)

type PrefixTreeNode struct {
	Component     string
	CurrentPrefix string
	IsFinal       bool
	Parent        *PrefixTreeNode
	Siblings      map[string]*PrefixTreeNode
	Matchers      map[PrefixSuffixFileMatcherRule]struct{}
}

func NewPrefixTree() *PrefixTreeNode {
	return &PrefixTreeNode{
		Component:     "/",
		CurrentPrefix: "/",
		IsFinal:       false,
		Parent:        nil,
		Siblings:      map[string]*PrefixTreeNode{},
		Matchers:      map[PrefixSuffixFileMatcherRule]struct{}{},
	}
}

func pathSplit(path string) []string {
	var result []string
	var last string
	for {
		if path = filepath.Clean(path); path == "/" {
			result = append([]string{path}, result...)
			break
		}
		path, last = filepath.Split(path)
		result = append([]string{last}, result...)
	}
	return result
}

func (node *PrefixTreeNode) Insert(ps PrefixSuffixFileMatcher, rule uint32) error {
	path := ps.Prefix
	pathParts := pathSplit(path)
	if len(pathParts) < 1 {
		return errors.New("path parts should contain at least 1 element")
	}
	if pathParts[0] != "/" {
		return errors.New("the first element of path parts should be always '/'")
	}

	currentNode := node
	for _, part := range pathParts {
		// we have already added '/' as the root node
		if part == "/" {
			continue
		}

		if nextNode, ok := currentNode.Siblings[part]; ok {
			nextNode.Matchers[PrefixSuffixFileMatcherRule{Matcher: ps, Rule: rule}] = struct{}{}
			currentNode = nextNode
		} else {
			newNode := &PrefixTreeNode{
				Component:     part,
				CurrentPrefix: filepath.Join(currentNode.CurrentPrefix, part),
				IsFinal:       false,
				Parent:        currentNode,
				Siblings:      map[string]*PrefixTreeNode{},
				Matchers: map[PrefixSuffixFileMatcherRule]struct{}{
					{Matcher: ps, Rule: rule}: struct{}{},
				},
			}
			currentNode.Siblings[part] = newNode
			currentNode = newNode
		}

		// now walk until the roo and update the matchers
		for nd := currentNode.Parent; nd != nil; nd = nd.Parent {
			nd.Matchers[PrefixSuffixFileMatcherRule{Matcher: ps, Rule: rule}] = struct{}{}
		}
	}
	// mark the terminal node as final
	currentNode.IsFinal = true

	return nil
}

type stack struct {
	items []*PrefixTreeNode
}

func (s *stack) push(item *PrefixTreeNode) {
	s.items = append(s.items, item)
}

func (s *stack) pop() *PrefixTreeNode {
	if len(s.items) == 0 {
		return nil
	}
	top := len(s.items) - 1
	item := s.items[top]
	s.items = s.items[:top]
	return item
}

func (s *stack) empty() bool {
	return len(s.items) == 0
}

func (node *PrefixTreeNode) isWalkPrefix() bool {
	// if the first node is non-final, then we don't need to walk that
	if node == nil || !node.IsFinal {
		return false
	}

	// not we know that the first node is final
	// in order to be considered as walk prefix, all the remaining
	// nodes until the root should be non-finbal
	for {
		node = node.Parent
		if node == nil {
			break
		}
		if node.IsFinal {
			return false
		}
	}
	return true
}

func (node *PrefixTreeNode) Traverse() []PrefixSuffixFileMatchers {
	var res []PrefixSuffixFileMatchers
	if node == nil {
		return res
	}

	var s stack
	s.push(node)
	for !s.empty() {
		n := s.pop()

		if n.isWalkPrefix() {
			res = append(res, PrefixSuffixFileMatchers{
				WalkPrefix: n.CurrentPrefix,
				Matchers:   n.Matchers,
			})
		}

		for _, node := range n.Siblings {
			s.push(node)
		}
	}

	return res
}
