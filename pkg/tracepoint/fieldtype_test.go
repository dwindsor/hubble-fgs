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
package tracepoint

import (
	"reflect"
	"testing"
)

func TestTracepointFieldParsing(t *testing.T) {
	tests := []struct {
		s  string
		ty interface{}
	}{
		{
			"unsigned short common_type",
			&Field{
				Name: "common_type",
				Type: IntTy{
					Base:     IntTyShort,
					Unsigned: true,
				},
			},
		}, {
			"int common_pid",
			&Field{
				Name: "common_pid",
				Type: IntTy{
					Base:     IntTyInt,
					Unsigned: false,
				},
			},
		}, {
			"pid_t pid",
			&Field{
				Name: "pid",
				Type: PidTy{},
			},
		}, {
			"char comm[16]",
			&Field{
				Name: "comm",
				Type: ArrayTy{
					Ty: IntTy{
						Base:     IntTyChar,
						Unsigned: false,
					},
					Size: 16,
				},
			},
		}, {
			"unsigned long clone_flags",
			&Field{
				Name: "clone_flags",
				Type: IntTy{
					Base:     IntTyLong,
					Unsigned: true,
				},
			},
		}, {
			"unsigned long long ull",
			&Field{
				Name: "ull",
				Type: IntTy{
					Base:     IntTyLongLong,
					Unsigned: true,
				},
			},
		}, {
			"unsigned buf_flags",
			&Field{
				Name: "buf_flags",
				Type: IntTy{
					Base:     IntTyInt,
					Unsigned: true,
				},
			},
		}, {
			"u8 flags",
			&Field{
				Name: "flags",
				Type: IntTy{
					Base:     IntTyInt8,
					Unsigned: true,
				},
			},
		}, {
			"u16 flags",
			&Field{
				Name: "flags",
				Type: IntTy{
					Base:     IntTyInt16,
					Unsigned: true,
				},
			},
		}, {
			"u32 flags",
			&Field{
				Name: "flags",
				Type: IntTy{
					Base:     IntTyInt32,
					Unsigned: true,
				},
			},
		}, {
			"u64 flags",
			&Field{
				Name: "flags",
				Type: IntTy{
					Base:     IntTyInt64,
					Unsigned: true,
				},
			},
		}, {
			"bool test",
			&Field{
				Name: "test",
				Type: BoolTy{},
			},
		}, {
			"dma_addr_t addr",
			&Field{
				Name: "addr",
				Type: DmaAddrTy{},
			},
		}, {
			"const char * buf",
			&Field{
				Name: "buf",
				Type: PointerTy{
					Ty:    IntTy{Base: IntTyChar, Unsigned: false},
					Const: true,
				},
			},
		},
	}

	for _, test := range tests {
		resTy, err := parseField(test.s)
		expectedTy := test.ty
		if err != nil {
			t.Logf("Error parsing %s: %s", test.s, err)
			t.Fail()
		} else if !reflect.DeepEqual(expectedTy, resTy) {
			t.Logf("Unexpected parsing result\nexpected:%+v\nresult:%+v\n", expectedTy, resTy)
			t.Fail()
		}
	}
}
