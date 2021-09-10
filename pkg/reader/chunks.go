//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package reader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/yalue/native_endian"
)

// TypedChunkIterator is an utility for iterating over a stream of
// [ type (u32) | size (u32) | payload ]
// Type and size are in the native byte-order.
type TypedChunkIterator struct {
	buf *bytes.Buffer
	err error
}

func NewTypedChunkIterator(buf []byte) *TypedChunkIterator {
	return &TypedChunkIterator{bytes.NewBuffer(buf), nil}
}

func (it *TypedChunkIterator) readNativeUint32() (uint32, error) {
	var x uint32
	if err := binary.Read(it.buf, native_endian.NativeEndian(), &x); err != nil {
		return 0, err
	}
	return x, nil
}

// Err an error if one occurred.
func (it *TypedChunkIterator) Err() error {
	return it.err
}

// Next returns the next chunk or false if no more remain or an error occurred.
// Use Err() to check if an error occurred or the end was reached.
func (it *TypedChunkIterator) Next() ([]byte, uint32, bool) {
	ty, err := it.readNativeUint32()
	if err != nil && err != io.EOF {
		it.err = err
		return nil, 0, false
	}
	if ty == 0 {
		fmt.Printf("ty=%d, stopping\n", ty)
		return nil, 0, false
	}
	fmt.Printf("read chunk ty=%d\n", ty)

	size, err := it.readNativeUint32()
	if err != nil {
		it.err = fmt.Errorf("failed to read %d > %d", size, it.buf.Len())
		return nil, 0, false
	}
	fmt.Printf("read chunk size=%d\n", size)
	if it.buf.Len() < int(size) {
		it.err = fmt.Errorf("chunk size overruns the buffer: %d > %d", size, it.buf.Len())
		return nil, 0, false
	}

	return it.buf.Next(int(size)), ty, true
}

func (it *TypedChunkIterator) NextString() (string, uint32, bool) {
	b, typ, ok := it.Next()
	return string(b), typ, ok
}
