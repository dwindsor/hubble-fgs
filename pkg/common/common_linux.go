// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package common

import (
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	"golang.org/x/sys/unix"
)

func InitHostNamespaces() (*tetragon.Namespaces, error) {
	return namespace.InitHostNamespace()
}

func DefaultABI() (string, error) {
	return syscallinfo.DefaultABI()
}

func GetSyscallName(abi string, sysID int) (string, error) {
	return syscallinfo.GetSyscallName(abi, sysID)
}

func ClockGettime(clockid int32, clockTime *syscall.Timespec) (err error) {
	return unix.ClockGettime(clockid, (*unix.Timespec)(unsafe.Pointer(clockTime)))
}
