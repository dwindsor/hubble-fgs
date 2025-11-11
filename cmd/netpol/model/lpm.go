package model

import (
	"fmt"
	"math/bits"
	"net/netip"
)

type LPMAPI[Value any] interface {
	LookupPrefix(prefix netip.Prefix) (value Value, found bool)
	Insert(prefix netip.Prefix, value Value) error
}

type LPM4[Value any] struct {
	lpm *lpm[Value]
}

func NewLPM4[Value any]() LPM4[Value] {
	return LPM4[Value]{
		lpm: &lpm[Value]{
			root:         nil,
			maxPrefixLen: 32,
			keySize:      4,
		},
	}
}

func (lpm4 LPM4[Value]) Insert(prefix netip.Prefix, value Value) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("%q is not IPv4 prefix", prefix)
	}
	return lpm4.lpm.Insert(LPMKey{
		PrefixLen: prefix.Bits(),
		Data:      prefix.Addr().AsSlice(),
	}, value)
}

func (lpm4 LPM4[Value]) LookupPrefix(prefix netip.Prefix) (value Value, found bool) {
	if !prefix.Addr().Is4() {
		return value, false
	}
	return lpm4.lpm.Lookup(LPMKey{
		PrefixLen: prefix.Bits(),
		Data:      prefix.Addr().AsSlice(),
	})
}

func (lpm4 LPM4[Value]) LookupAddr(addr netip.Addr) (value Value, found bool) {
	if !addr.Is4() {
		return value, false
	}
	return lpm4.lpm.Lookup(LPMKey{
		PrefixLen: 32,
		Data:      addr.AsSlice(),
	})
}

func (lpm4 LPM4[Value]) Print() {
	lpm4.print(lpm4.lpm.root, "")
}

func (lpm4 LPM4[Value]) print(node *lpmNode[Value], indent string) {
	if node == nil {
		return
	}
	addr, _ := netip.AddrFromSlice(node.key)
	prefix := netip.PrefixFrom(addr, node.prefixLen)
	img := ""
	if node.imaginary {
		img = " *"
	}
	fmt.Printf("%s%s => %v%s\n", indent, prefix, node.value, img)
	indent += "  "
	lpm4.print(node.children[0], indent)
	lpm4.print(node.children[1], indent)
}

type LPM6[Value any] struct {
	lpm *lpm[Value]
}

func NewLPM6[Value any]() LPM6[Value] {
	return LPM6[Value]{
		lpm: &lpm[Value]{
			root:         nil,
			maxPrefixLen: 128,
			keySize:      16,
		},
	}
}

func (lpm6 LPM6[Value]) Insert(prefix netip.Prefix, value Value) error {
	if !prefix.Addr().Is6() {
		return fmt.Errorf("%q is not IPv6 prefix", prefix)
	}
	return lpm6.lpm.Insert(LPMKey{
		PrefixLen: prefix.Bits(),
		Data:      prefix.Addr().AsSlice(),
	}, value)
}

func (lpm6 LPM6[Value]) LookupPrefix(prefix netip.Prefix) (Value, bool) {
	if !prefix.Addr().Is6() {
		var z Value
		return z, false
	}
	return lpm6.lpm.Lookup(LPMKey{
		PrefixLen: prefix.Bits(),
		Data:      prefix.Addr().AsSlice(),
	})
}

func (lpm6 LPM6[Value]) LookupAddr(addr netip.Addr) (value Value, found bool) {
	if !addr.Is6() {
		return value, false
	}
	return lpm6.lpm.Lookup(LPMKey{
		PrefixLen: 128,
		Data:      addr.AsSlice(),
	})
}

type lpm[Value any] struct {
	root         *lpmNode[Value]
	maxPrefixLen int
	keySize      int
}

type LPMKey struct {
	PrefixLen int
	Data      []byte
}

type lpmNode[Value any] struct {
	children  [2]*lpmNode[Value]
	key       []byte
	value     Value
	prefixLen int
	imaginary bool
}

func (lpm *lpm[Value]) Insert(key LPMKey, value Value) error {
	if key.PrefixLen > lpm.maxPrefixLen {
		return fmt.Errorf("prefix length %d larger than max %d", key.PrefixLen, lpm.maxPrefixLen)
	}
	newNode := &lpmNode[Value]{
		children:  [2]*lpmNode[Value]{},
		key:       key.Data,
		value:     value,
		prefixLen: key.PrefixLen,
		imaginary: false,
	}

	nodep := &lpm.root
	node := *nodep

	var matchLen int
	for node != nil {
		matchLen = lpm.longestMatch(node, key)
		if node.prefixLen != matchLen ||
			node.prefixLen == key.PrefixLen ||
			node.prefixLen == lpm.maxPrefixLen {
			break
		}
		nodep = &node.children[getBitAt(key.Data, node.prefixLen)]
		node = *nodep
	}

	switch {
	case node == nil:
		*nodep = newNode
		return nil
	case node.prefixLen == matchLen:
		newNode.children = node.children
		*nodep = newNode
		return nil
	case matchLen == key.PrefixLen:
		index := getBitAt(node.key, matchLen)
		newNode.children[index] = node
		*nodep = newNode
	default:
		imaginary := &lpmNode[Value]{
			children:  [2]*lpmNode[Value]{},
			key:       node.key,
			prefixLen: matchLen,
			imaginary: true,
		}
		switch getBitAt(key.Data, matchLen) {
		case 0:
			imaginary.children[0] = newNode
			imaginary.children[1] = node
		case 1:
			imaginary.children[0] = node
			imaginary.children[1] = newNode
		}
		*nodep = imaginary
	}

	return nil
}

func (lpm *lpm[Value]) longestMatch(n *lpmNode[Value], key LPMKey) int {
	prefixLen := 0
	for i := range lpm.keySize {
		matchLenInByte := bits.LeadingZeros8(n.key[i] ^ key.Data[i])
		prefixLen += matchLenInByte
		if n := min(n.prefixLen, key.PrefixLen); prefixLen >= n {
			return n
		}
		if matchLenInByte < 8 {
			// Less than full byte matched, we can stop.
			break
		}
	}
	return prefixLen
}

func (lpm *lpm[Value]) Lookup(key LPMKey) (value Value, ok bool) {
	var closest *lpmNode[Value]
	node := lpm.root
	for node != nil {
		matchLen := lpm.longestMatch(node, key)
		if matchLen == lpm.maxPrefixLen {
			return node.value, true
		}
		if matchLen < node.prefixLen {
			break
		}
		if !node.imaginary {
			closest = node
		}
		node = node.children[getBitAt(key.Data, node.prefixLen)]
	}
	if closest != nil {
		return closest.value, true
	}
	return value, false
}

func getBitAt(data []byte, index int) int {
	return int(data[index/8]>>(7-(index%8))) & 1
}
