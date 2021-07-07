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

#include "btf.h"
#include "libbpf.h"

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

static long getError(void *ptr)
{
	if ((unsigned long)ptr >= (unsigned long)-MAX_ERRNO) {
		return -(long)ptr;
	}
	return 0;
}

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
	"fmt"
	"unsafe"
)

// BTF is a wrapper for struct btf *
type BTF uintptr

const BTFNil = BTF(0)

// NewBTF creates a new BTF object based on the file in the given path
func NewBTF(path string) (BTF, error) {
	ret := C.getBtf(C.CString(path))
	if err := C.getError(ret); err != 0 {
		return BTF(0), fmt.Errorf("failed to parse BTF: %d", err)
	}
	return BTF(uintptr(ret)), nil
}

// Close releases the resources of the BTF object
func (btf BTF) Close() {
	ptr := uintptr(btf)
	C.freeBtf(unsafe.Pointer(ptr))
}

func (btf BTF) AddEnum(name string, value int) int {
	ptr := uintptr(btf)
	ret := C.addEnumBtf(unsafe.Pointer(ptr), C.CString(name), C.int(value))
	return int(ret)
}

func (btf BTF) AddEnumValue(name string, value int) int {
	ptr := uintptr(btf)
	ret := C.addEnumBtfValue(unsafe.Pointer(ptr), C.CString(name), C.int(value))
	return int(ret)
}
