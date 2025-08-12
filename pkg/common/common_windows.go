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

	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/ktime"
	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/api/v1/tetragon"

	consts "github.com/isovalent/hubble-fgs/pkg/constants"
)

var (
	dll                     = syscall.MustLoadDLL("kernel32.dll")
	queryCounter            = dll.MustFindProc("QueryPerformanceCounter")
	queryFrequency          = dll.MustFindProc("QueryPerformanceFrequency")
	getSystemTimeAsFileTime = dll.MustFindProc("GetSystemTimeAsFileTime")
	getTickCount            = dll.MustFindProc("GetTickCount64")
	booTimeEpoch            = GetBootTimeInWindowsEpoch()
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

func getBootTimeNanoseconds() uint64 {
	var freq, counter uint64
	queryFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	if freq == 0 {
		ticks, _, _ := getTickCount.Call()
		counter = uint64(ticks)
		freq = 1000
	} else {
		queryCounter.Call(uintptr(unsafe.Pointer(&counter)))
	}
	var multiplier float64
	multiplier = float64(10000000000) / float64(freq)
	return uint64(float64(counter) * multiplier)
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

func GetSystemTimeAsFileTime() windows.Filetime {
	var ft windows.Filetime
	getSystemTimeAsFileTime.Call(uintptr(unsafe.Pointer(&ft)))
	return ft
}

// This function returns the value of system boot in 100 NS since 1600

func GetBootTimeInWindowsEpoch() uint64 {
	ft := GetSystemTimeAsFileTime()
	kTime := uint64((int64(ft.HighDateTime) << 32) + int64(ft.LowDateTime))
	var bootTime uint64
	queryCounter.Call(uintptr(unsafe.Pointer(&bootTime)))
	bTime := getBootTimeNanoseconds()
	return (kTime - (bTime / 1000))

}

func KTimeToWindowsEpoch(ktime uint64) uint64 {
	return (ktime/100 + booTimeEpoch)
}
