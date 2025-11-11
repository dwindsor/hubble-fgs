package model

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLPM4(t *testing.T) {
	lpm4 := NewLPM4[int]()

	cases := []struct {
		addr string
		len  int
	}{
		{"10.1.1.1", 32},    // 0
		{"10.0.0.0", 8},     // 1
		{"192.168.1.0", 24}, // 2
		{"192.168.1.5", 32}, // 3
	}

	for i, c := range cases {
		lpm4.Insert(netip.MustParsePrefix(fmt.Sprintf("%s/%d", c.addr, c.len)), i)
	}
	lpm4.Print()

	for i, c := range cases {
		v, found := lpm4.LookupAddr(netip.MustParseAddr(c.addr))
		assert.True(t, found)
		assert.Equal(t, i, v)
	}
	v, found := lpm4.LookupAddr(netip.MustParseAddr("10.0.0.1"))
	assert.True(t, found)
	assert.Equal(t, 1, v)
	v, found = lpm4.LookupAddr(netip.MustParseAddr("192.168.1.4"))
	assert.True(t, found)
	assert.Equal(t, 2, v)
	v, found = lpm4.LookupAddr(netip.MustParseAddr("192.168.1.6"))
	assert.True(t, found)
	assert.Equal(t, 2, v)

	lpm4.Insert(netip.MustParsePrefix("10.1.1.1/32"), 999)
	v, found = lpm4.LookupAddr(netip.MustParseAddr("10.1.1.1"))
	assert.True(t, found)
	assert.Equal(t, 999, v)
}

func TestLPM6(t *testing.T) {
	lpm6 := NewLPM6[int]()

	cases := []struct {
		addr string
		len  int
	}{
		{"10::1", 128},   // 0
		{"10::", 64},     // 1
		{"2001::", 64},   // 2
		{"2001::5", 128}, // 3
	}

	for i, c := range cases {
		lpm6.Insert(netip.MustParsePrefix(fmt.Sprintf("%s/%d", c.addr, c.len)), i)
	}

	for i, c := range cases {
		v, found := lpm6.LookupAddr(netip.MustParseAddr(c.addr))
		assert.True(t, found)
		assert.Equal(t, i, v)
	}
	v, found := lpm6.LookupAddr(netip.MustParseAddr("10::2"))
	assert.True(t, found)
	assert.Equal(t, 1, v)
	v, found = lpm6.LookupAddr(netip.MustParseAddr("2001::1"))
	assert.True(t, found)
	assert.Equal(t, 2, v)
	v, found = lpm6.LookupAddr(netip.MustParseAddr("2001::6"))
	assert.True(t, found)
	assert.Equal(t, 2, v)
}
