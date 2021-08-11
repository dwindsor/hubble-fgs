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

/*
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"syscall"
	"time"
)

func getUserHZ() int64 {
	return int64(C.sysconf(C._SC_CLK_TCK))
}

type CPUUsage struct {
	SystemTime time.Duration
	UserTime   time.Duration
	MaxRss     int64
}

type CPUUsageTarget int

const (
	CPU_USAGE_ALL_THREADS = syscall.RUSAGE_SELF
	CPU_USAGE_THIS_THREAD = syscall.RUSAGE_THREAD
)

func CPUUsageFromRusage(rusage *syscall.Rusage) (cpuUsage CPUUsage) {
	cpuUsage.UserTime = timevalToDuration(rusage.Utime)
	cpuUsage.SystemTime = timevalToDuration(rusage.Stime)
	cpuUsage.MaxRss = rusage.Maxrss
	return
}

func CPUUsageFromCPUAcct(containerID string) CPUUsage {
	userHz := time.Duration(getUserHZ())
	cpuAcctFilename := fmt.Sprintf("/sys/fs/cgroup/cpuacct/docker/%s/cpuacct.stat", containerID)

	cpuAcctStat, err := ioutil.ReadFile(cpuAcctFilename)
	if err != nil {
		log.Printf("Could not read cpuacct.stat: %s\n", err)
		return CPUUsage{}
	}

	var userTicks, sysTicks int64
	if _, err := fmt.Sscanf(string(cpuAcctStat), "user %d\nsystem %d\n", &userTicks, &sysTicks); err != nil {
		log.Printf("Failed to parse cpuacct.stat: %s\n", err)
		return CPUUsage{}
	}

	return CPUUsage{
		UserTime: (time.Duration(userTicks) * time.Second) / userHz,
		SystemTime: (time.Duration(sysTicks) * time.Second) / userHz,
		MaxRss: 0,
	}
}

func GetCPUUsage(tgt CPUUsageTarget) CPUUsage {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(int(tgt), &rusage); err != nil {
		log.Printf("Getrusage failed: %v", err)
		return CPUUsage{}
	}
	return CPUUsageFromRusage(&rusage)
}

func timevalToDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second +
		time.Duration(tv.Usec)*time.Microsecond
}

func (cu CPUUsage) Sub(cu2 CPUUsage) CPUUsage {
	cu.UserTime -= cu2.UserTime
	cu.SystemTime -= cu2.SystemTime
	return cu
}

func (cu CPUUsage) String() string {
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

func ProbeTCPPort(port int) bool {
	probeTimeout := 10 * time.Second
	attempts := 20
	delay := probeTimeout / time.Duration(attempts)

	ready := false
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for attempt := 0; attempt < attempts; attempt++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(delay)
	}
	return ready
}
