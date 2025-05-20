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
	"time"
	"unsafe"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/ktime"
	consts "github.com/isovalent/hubble-fgs/pkg/constants"
)

var (
	dll            = syscall.MustLoadDLL("kernel32.dll")
	queryCounter   = dll.MustFindProc("QueryPerformanceCounter")
	queryFrequency = dll.MustFindProc("QueryPerformanceFrequency")
)

func InitHostNamespaces() (*tetragon.Namespaces, error) {
	return nil, nil
}

func DefaultABI() (string, error) {
	return "", nil
}

func GetSyscallName(abi string, sysID int) (string, error) {
	return "", constants.ErrWindowsNotSupported
}

func getBootTimeNanoseconds() int64 {
	var freq, counter int64
	queryFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	queryCounter.Call(uintptr(unsafe.Pointer(&counter)))
	return (counter * 1e9) / freq
}

func ClockGettime(clockid int32, clockTime *syscall.Timespec) (err error) {
	var nowTime time.Duration
	if clockid == consts.CLOCK_MONOTONIC {
		nowTime, err = ktime.Monotonic()
		if err != nil {
			return err
		}
	} else {
		nowTime = time.Duration(getBootTimeNanoseconds())
	}

	*clockTime = syscall.Timespec{
		Sec:  int64(nowTime / time.Second), // Extract seconds
		Nsec: int64(nowTime % time.Second), // Extract nanoseconds
	}
	return nil
}
