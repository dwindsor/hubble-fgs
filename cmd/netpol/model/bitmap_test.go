package model

import (
	"fmt"
	"slices"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/require"
)

func TestBitMap(t *testing.T) {
	size := 131
	bm := NewBitMap(size)
	for i := range size {
		require.False(t, bm.Get(i))
	}
	bm.Set(0)
	require.True(t, bm.Get(0))
	require.False(t, bm.Get(1))
	bm.Set(64)
	require.False(t, bm.Get(63))
	require.True(t, bm.Get(64))
	require.False(t, bm.Get(65))
	for i, isSet := range bm.All() {
		switch i {
		case 0:
			require.True(t, isSet)
		case 64:
			require.True(t, isSet)
		default:
			require.False(t, isSet, "bit %d unexpectedly set", i)
		}
	}

	for i := range size {
		bm.Set(i)
		require.True(t, bm.Get(i))
	}
	j := 0
	for i, isSet := range bm.All() {
		require.Equal(t, j, i)
		require.True(t, isSet)
		j++
	}
	require.Equal(t, size, j)

	for i := range size - 1 {
		bm.Unset(i)
		require.False(t, bm.Get(i))
		require.True(t, bm.Get(i+1))
	}
	bm.Unset(size - 1)

	j = 0
	for i, isSet := range bm.All() {
		require.Equal(t, j, i)
		require.False(t, isSet)
		j++
	}
	require.Equal(t, size, j)
}

func TestBitMapQuick(t *testing.T) {
	bm := NewBitMap(255)
	wasSet := [256]bool{}
	err := quick.Check(func(index uint8, shouldSet bool) bool {
		if wasSet[index] != bm.Get(int(index)) {
			return false
		}
		if shouldSet {
			bm.Set(int(index))
			wasSet[index] = true
			if !bm.Get(int(index)) {
				return false
			}
		} else {
			bm.Unset(int(index))
			if bm.Get(int(index)) {
				return false
			}
		}
		wasSet[index] = shouldSet

		for i, isSet := range bm.All() {
			if wasSet[i] != isSet {
				return false
			}
		}
		return true
	}, nil)
	require.NoError(t, err)
}

func TestOrBitMap(t *testing.T) {
	bm1, bm2 := NewBitMap(128), NewBitMap(128)
	setBits := slices.Collect(OrBits(bm1, bm2))
	require.Empty(t, setBits)
	bm1.Set(56)
	bm1.Set(57)
	bm1.Set(67)
	bm2.Set(68)
	setBits = slices.Collect(OrBits(bm1, bm2))
	require.Equal(t, []int{56, 57, 67, 68}, setBits)
	bm1.Set(68)
	setBits = slices.Collect(OrBits(bm1, bm2))
	require.Equal(t, []int{56, 57, 67, 68}, setBits)
	bm2.Unset(68)
	setBits = slices.Collect(OrBits(bm1, bm2))
	require.Equal(t, []int{56, 57, 67, 68}, setBits)

	bm1, bm2 = NewBitMap(128), NewBitMap(128)
	for i := range 128 {
		bm1.Set(i)
	}
	fmt.Printf("bm1: %b, bm2: %b\n", bm1.buf, bm2.buf)
	setBits = slices.Collect(OrBits(bm1, bm2))
	require.Len(t, setBits, 128)
	setBits = slices.Collect(OrBits(bm2, bm1))
	require.Len(t, setBits, 128)
	bm1 = NewBitMap(128)
	for i := range 128 {
		if i < 64 {
			bm1.Set(i)
		} else {
			bm2.Set(i)
		}
	}
	setBits = slices.Collect(OrBits(bm1, bm2))
	require.Len(t, setBits, 128)
	setBits = slices.Collect(OrBits(bm2, bm1))
	require.Len(t, setBits, 128)
}
