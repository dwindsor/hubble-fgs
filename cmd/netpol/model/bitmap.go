package model

import (
	"fmt"
	"iter"
	"math/bits"
	"slices"
)

type BitMap struct {
	buf  []uint64
	bits int
}

func NewBitMap(numBits int) BitMap {
	return BitMap{
		buf:  make([]uint64, 1+numBits/64),
		bits: numBits,
	}
}

func (bm BitMap) Clone() BitMap {
	return BitMap{
		buf:  slices.Clone(bm.buf),
		bits: bm.bits,
	}
}

func (bm BitMap) Get(index int) bool {
	if index > bm.bits {
		panic(fmt.Sprintf("index %d (>%d) out of bounds", index, bm.bits))
	}
	word := bm.buf[index/64]
	return word&uint64(1<<(index%64)) != 0
}

func (bm BitMap) Set(index int) {
	if index > bm.bits {
		panic(fmt.Sprintf("index %d (>%d) out of bounds", index, bm.bits))
	}
	bm.buf[index/64] |= 1 << (index % 64)
}

func (bm BitMap) Unset(index int) {
	if index > bm.bits {
		panic(fmt.Sprintf("index %d (>%d) out of bounds", index, bm.bits))
	}
	bm.buf[index/64] &= ^(1 << (index % 64))
}

func (bm BitMap) All() iter.Seq2[int, bool] {
	return func(yield func(index int, isSet bool) bool) {
		i := 0
		for _, w := range bm.buf {
			for j := range 64 {
				if !yield(i, w&(uint64(1)<<j) != 0) {
					return
				}
				i++
				if i >= bm.bits {
					break
				}
			}
		}
	}
}

func OrBits(a, b BitMap) iter.Seq[int] {
	if a.bits != b.bits {
		panic("OrBits: BitMaps are different sizes")
	}
	return func(yield func(index int) bool) {
		for i, w := range a.buf {
			w |= b.buf[i]
			for {
				pos := bits.TrailingZeros64(w)
				if pos >= 64 {
					break
				}
				if !yield(i*64 + pos) {
					return
				}
				w &= ^(uint64(1) << pos)
			}
		}
	}
}

func AndBits(a, b BitMap) iter.Seq[int] {
	if a.bits != b.bits {
		panic("AndBits: BitMaps are different sizes")
	}
	return func(yield func(index int) bool) {
		for i, w := range a.buf {
			w &= b.buf[i]
			for {
				pos := bits.TrailingZeros64(w)
				if pos >= 64 {
					break
				}
				if !yield(i*64 + pos) {
					return
				}
				w &= ^(uint64(1) << pos)
			}
		}
	}
}
