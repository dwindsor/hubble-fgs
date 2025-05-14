// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bench

import (
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/vishvananda/netns"
)

type CPUPercentages struct {
	SourceCpuUser   float64
	SourceCpuSystem float64
	RemoteCpuUser   float64
	RemoteCpuSystem float64
}

type CPUUsage struct {
	SystemTime      time.Duration
	UserTime        time.Duration
	MaxRss          int64
	ContextSwitches int64
}

type CPUUsageTarget int

const (
	CPU_USAGE_ALL_THREADS = constants.RUSAGE_SELF
	CPU_USAGE_THIS_THREAD = constants.RUSAGE_THREAD
)

func (cu CPUUsage) Sub(cu2 CPUUsage) CPUUsage {
	cu.UserTime -= cu2.UserTime
	cu.SystemTime -= cu2.SystemTime
	cu.ContextSwitches -= cu2.ContextSwitches
	return cu
}

func (cu CPUUsage) Add(cu2 CPUUsage) CPUUsage {
	cu.UserTime += cu2.UserTime
	cu.SystemTime += cu2.SystemTime
	return cu
}

func (cu CPUUsage) String() string {
	return fmt.Sprintf("system=%s, user=%s, rss=%d, ctxsw=%d", cu.SystemTime, cu.UserTime, cu.MaxRss, cu.ContextSwitches)
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

func ProbeTCPPort(port int, ns *netns.NsHandle) bool {
	if ns != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		origns, _ := netns.Get()
		defer origns.Close()
		defer netns.Set(origns)

		if err := netns.Set(*ns); err != nil {
			return false
		}
	}

	probeTimeout := 30 * time.Second
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
