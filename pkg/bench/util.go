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
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	CPU_USAGE_ALL_THREADS = syscall.RUSAGE_SELF
	CPU_USAGE_THIS_THREAD = syscall.RUSAGE_THREAD
)

func CPUUsageFromRusage(rusage *syscall.Rusage) (cpuUsage CPUUsage) {
	cpuUsage.UserTime = timevalToDuration(rusage.Utime)
	cpuUsage.SystemTime = timevalToDuration(rusage.Stime)
	cpuUsage.MaxRss = rusage.Maxrss
	cpuUsage.ContextSwitches = rusage.Nivcsw + rusage.Nvcsw
	return
}

func CPUUsageFromCPUAcct(containerID string) CPUUsage {

	rss := int64(0)
	memStatFilename := fmt.Sprintf("/sys/fs/cgroup/memory/docker/%s/memory.stat", containerID)
	memStat, err := os.ReadFile(memStatFilename)
	if err != nil {
		// Fallback to the path observed in CI
		memStatFilename = fmt.Sprintf("/sys/fs/cgroup/memory/actions_job/%s/memory.stat", containerID)
		memStat, err = os.ReadFile(memStatFilename)
	}

	if err != nil {
		log.Printf("Failed to read memory.stat: %s\n", err)
	} else {
		for _, line := range strings.Split(string(memStat), "\n") {
			if strings.HasPrefix(line, "total_rss ") {
				if _, err := fmt.Sscanf(line, "total_rss %d", &rss); err != nil {
					log.Printf("Failed to parse memory.stat ('%s'): %s\n", line, err)
				}
			}
		}
	}

	readUsageNanos := func(suffix string) uint64 {
		cpuStatFilename := fmt.Sprintf("/sys/fs/cgroup/cpuacct/docker/%s/cpuacct.usage_%s", containerID, suffix)
		cpuStat, err := os.ReadFile(cpuStatFilename)
		if err != nil {
			// Fallback to the path observed in CI
			cpuStatFilename = fmt.Sprintf("/sys/fs/cgroup/cpu,cpuacct/actions_job/%s/cpuacct.usage_%s", containerID, suffix)
			cpuStat, err = os.ReadFile(cpuStatFilename)
		}
		if err != nil {
			log.Printf("Failed to read cpuacct.usage_%s: %s\n", suffix, err)
			return 0
		}
		usage, err := strconv.ParseUint(strings.TrimSpace(string(cpuStat)), 10, 64)
		if err != nil {
			log.Printf("Failed to parse cpuacct.usage_%s: %s (\"%s\")\n", suffix, err, string(cpuStat))
			return 0
		}
		return usage
	}

	return CPUUsage{
		UserTime:   time.Duration(readUsageNanos("user")),
		SystemTime: time.Duration(readUsageNanos("sys")),
		MaxRss:     rss,
	}
}

// CPUUsageFromTime parses the CPU usage from /usr/bin/time output
// Assumes POSIX format, use "-p" with the GNU version.
// TODO: Could also use the "time -v" format which both GNU and Busybox versions support.
// It includes maxrss and context switches. Annoying if it's interspersed with other output
// that also needs to be parsed. Perhaps nicer would be to just use the GNU version with
// custom format, but this would require custom docker images for nginx, h2load and netperf.
func CPUUsageFromTime(output string, otherLine func(line string)) (cpuUsage CPUUsage, err error) {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "user") {
			var secs float64
			if _, err = fmt.Sscanf(line, "user %f", &secs); err != nil {
				err = fmt.Errorf("failed to parse user line '%s': %w", line, err)
				return
			}
			cpuUsage.UserTime = time.Duration(secs * float64(time.Second))
		} else if strings.HasPrefix(line, "sys") {
			var secs float64
			if _, err = fmt.Sscanf(line, "sys %f", &secs); err != nil {
				err = fmt.Errorf("failed to parse sys line '%s': %w", line, err)
				return
			}
			cpuUsage.SystemTime = time.Duration(secs * float64(time.Second))
		} else if line != "" && !strings.HasPrefix(line, "real") {
			otherLine(line)
		}

	}
	return
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
