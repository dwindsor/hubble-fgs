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
	"testing"

	"github.com/yalue/native_endian"
)

func TestEmptyTypedChunkIterator(t *testing.T) {
	iter := NewTypedChunkIterator([]byte{})
	_, _, ok := iter.Next()
	if ok {
		t.Error("expected Next() to return false on empty buffer")
	}
	if iter.Err() != nil {
		t.Errorf("expected Err() to be nil instead of: %s", iter.Err())
	}
}

func TestTypedChunkIterator(t *testing.T) {
	buf := new(bytes.Buffer)

	typ := uint32(1)
	size := uint32(4)
	binary.Write(buf, native_endian.NativeEndian(), &typ)
	binary.Write(buf, native_endian.NativeEndian(), &size)
	buf.WriteString("abcd")

	typ = uint32(2)
	size = uint32(5)
	binary.Write(buf, native_endian.NativeEndian(), &typ)
	binary.Write(buf, native_endian.NativeEndian(), &size)
	buf.WriteString("hello")

	typ = uint32(0)
	size = uint32(0)
	binary.Write(buf, native_endian.NativeEndian(), &typ)
	binary.Write(buf, native_endian.NativeEndian(), &size)

	iter := NewTypedChunkIterator(buf.Bytes())

	chunk, typ, ok := iter.NextString()
	if !ok || typ != 1 || chunk != "abcd" {
		t.Errorf("Expected true:1:abcd, got %v:%d:%s",
			ok, typ, chunk)
	}
	chunk, typ, ok = iter.NextString()
	if !ok || typ != 2 || chunk != "hello" {
		t.Errorf("Expected true:1:abcd, got %v:%d:%s",
			ok, typ, chunk)
	}
	_, _, ok = iter.NextString()
	if ok {
		t.Error("Expected Next() to return false on typ=0")
	}
	if iter.Err() != nil {
		t.Errorf("Expected Err() to be nil instead of: %s", iter.Err())
	}
}

func TestBadTypedChunkIterator(t *testing.T) {
	buf := new(bytes.Buffer)

	// Test faulty size
	typ := uint32(1)
	size := uint32(8)
	binary.Write(buf, native_endian.NativeEndian(), &typ)
	binary.Write(buf, native_endian.NativeEndian(), &size)
	buf.WriteString("abcd")

	iter := NewTypedChunkIterator(buf.Bytes())

	chunk, typ, ok := iter.Next()
	if ok || typ != 0 || chunk != nil {
		t.Errorf("Expected false:0:nil, got %v:%d:%s",
			ok, typ, chunk)
	}

	if iter.Err() == nil {
		t.Error("Expected Err() to be non-nil")
	}
}
