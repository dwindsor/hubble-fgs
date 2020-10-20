// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stacktracetree

import (
	"fmt"
	"log"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/ksyms"
)

// Addr is an Address on the stacktrace tree
type Addr = uint64

// SttLabel is a key-value label
type SttLabel struct {
	Key interface{}
	Val interface{}
}

// SttNode is a tree node
type SttNode struct {
	Addr     Addr
	Count    int
	Symbol   *ksyms.FnOffset
	Labels   map[SttLabel]int
	Children map[Addr]*SttNode
}

func (n1 *SttNode) merge(n2 *SttNode) {
	if n1.Addr != n2.Addr {
		log.Fatalf("cannot merge incompatible nodes with addresses %x and %x", n1.Addr, n2.Addr)
	}

	n1.Count += n2.Count

	s1 := n1.Symbol
	s2 := n2.Symbol

	if s1 == nil && s2 == nil {
		// nothing to do
	} else if s1 != nil && s2 == nil {
		// nothing to do
	} else if s1 == nil && s2 != nil {
		n1.Symbol = s2
	} else if s1 != s2 {
		// both have symbols defined, but they are different, so
		// something is wrong
		log.Printf("error: different symbols (%s,%s) for the same address %x", s1.ToString(), s2.ToString(), n1.Addr)
	}

	for lbl, lblCount := range n2.Labels {
		n1.Labels[lbl] += lblCount
	}

	if len(n2.Children) > 0 {
		log.Fatal("TODO: implement children merging")
	}
}

// Sttree is a stacktrace tree
type Sttree struct {
	Root SttNode
}

// Stt is a single stacktrace
type Stt struct {
	nodes []*SttNode
}

// Append appends an entry to a stacktrace
func (p *Stt) Append(addr Addr, sym *ksyms.FnOffset, labels []SttLabel) {
	node := &SttNode{
		Addr:     addr,
		Count:    1,
		Symbol:   sym,
		Children: map[Addr]*SttNode{},
	}

	for _, label := range labels {
		node.Labels[label] = 1
	}

	p.nodes = append(p.nodes, node)
}

// CreateSttree creates a stacktrace tree
func CreateSttree() *Sttree {
	return &Sttree{
		Root: SttNode{
			Addr:     0,
			Count:    0,
			Symbol:   nil,
			Children: map[Addr]*SttNode{},
		},
	}
}

// AddStacktrace adds a stacktrace to the tree
func (t *Sttree) AddStacktrace(stt *Stt) {
	if len(stt.nodes) == 0 {
		return
	}

	t.Root.Count += stt.nodes[0].Count
	t.Root.addChildren(stt.nodes)
}

func (n *SttNode) addChildren(nodes []*SttNode) {
	if len(nodes) == 0 {
		return
	}

	node := nodes[0]
	addr := node.Addr
	child := n.Children[addr]
	if child == nil {
		n.Children[addr] = node
	} else {
		child.merge(node)
	}

	n.Children[addr].addChildren(nodes[1:])
}

func (n *SttNode) printNode(level int) {
	indent := strings.Repeat("  ", level)
	sym := ""
	if n.Symbol != nil {
		sym = n.Symbol.ToString()
	}
	fmt.Printf("%s0x%x (%s) count:%d\n", indent, n.Addr, sym, n.Count)

	for _, child := range n.Children {
		child.printNode(level + 1)
	}
}

// Print prints the tree
func (t *Sttree) Print() {
	t.Root.printNode(0)
}
