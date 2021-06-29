//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bench

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

type CpuUsage struct {
	SystemTime time.Duration
	UserTime   time.Duration
	MaxRss     int64
}

type CpuUsageTarget int

const (
	CPU_USAGE_ALL_THREADS = syscall.RUSAGE_SELF
	CPU_USAGE_THIS_THREAD = syscall.RUSAGE_THREAD
)

func GetCpuUsage(tgt CpuUsageTarget) (cpuUsage CpuUsage) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(int(tgt), &rusage); err != nil {
		log.Fatalf("Getrusage failed: %v", err)
		return
	}
	cpuUsage.UserTime = timevalToDuration(rusage.Utime)
	cpuUsage.SystemTime = timevalToDuration(rusage.Stime)
	cpuUsage.MaxRss = rusage.Maxrss
	return
}

func timevalToDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second +
		time.Duration(tv.Usec)*time.Microsecond
}

func (cu CpuUsage) Sub(cu2 CpuUsage) CpuUsage {
	cu.UserTime -= cu2.UserTime
	cu.SystemTime -= cu2.SystemTime
	return cu
}

func (cu CpuUsage) String() string {
	return fmt.Sprintf("system=%s, user=%s, rss=%d", cu.SystemTime, cu.UserTime, cu.MaxRss)
}

type CountingDiscardWriter struct {
	nbytes  int64
	nwrites int64
}

func (cw *CountingDiscardWriter) Write(p []byte) (n int, err error) {
	cw.nbytes += int64(len(p))
	cw.nwrites++
	return len(p), nil
}
