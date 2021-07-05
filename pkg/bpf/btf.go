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

// +build linux
package bpf

/*
#cgo CFLAGS:
#cgo LDFLAGS: -L../../lib -lbpf -lelf -lz

#include "libbpf.h"

static void *getBtf(const char *btf)
{
	return btf__parse(btf, NULL);
}

static int addEnumBtf(void *btf, char *name, int value)
{
	return btf__add_enum(btf, name, value);
}

static int addEnumBtfValue(void *btf, char *name, int value)
{
	return btf__add_enum_value(btf, name, value);
}

static void freeBtf(void *btfobj)
{
	btf__free(btfobj);
}
*/
import "C"

import (
	"unsafe"
)

func GetBTF(__btf string) uintptr {
	return uintptr(C.getBtf(C.CString(__btf)))
}

func AddEnumBtf(btf uintptr, name string, value int) int {
	ret := C.addEnumBtf(unsafe.Pointer(btf), C.CString(name), C.int(value))
	return int(ret)
}

func AddEnumBtfValue(btf uintptr, name string, value int) int {
	ret := C.addEnumBtfValue(unsafe.Pointer(btf), C.CString(name), C.int(value))
	return int(ret)
}

func FreeBTF(btf uintptr) {
	C.freeBtf(unsafe.Pointer(btf))
}
