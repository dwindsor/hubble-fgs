//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udp

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/timer"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"

	"golang.org/x/sys/unix"
)

const (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	udpStatsCacheSize    = 32000
)

type udpPseudoSocket struct {
	SAddr     [2]uint64
	SPort     uint16
	DAddr     [2]uint64
	DPort     uint16
	IPv6      uint8
	PsVersion uint64
}

type cookieVer struct {
	Cookie  uint64
	Version uint64
}

type udpStatsKey struct {
	Cookie    uint64
	Tuple     api.MsgIPTuple
	Version   uint64
	PsVersion uint64
}

var (
	UdpDeleteInterval = time.Duration(600 * time.Second)
	udpStatsEnable    = false

	stats *lru.Cache[udpStatsKey, api.UdpInfoValue]

	gcTimer = timer.NewPeriodicTimer("UDP GC Timer", runUdpGC, true)

	pseudoSockets       = make(map[cookieVer](map[udpPseudoSocket]bool))
	pseudoSocketsUpdate sync.Mutex
)

// emitUdpEvent builds a udpEvent and expects caller to set the correct Op value.
func createUdpStatsEvent(k *api.UdpInfoKey, v *api.UdpInfoValue, duration time.Duration) *layer3.MsgIPWithStatsEventUnix {
	unix := layer3.MsgIPWithStatsEventUnix{}
	unix.Msg = &api.MsgIPWithStatsEvent{}

	unix.Msg.Common = processapi.MsgCommon{
		Op:    0,
		Size:  1,
		Ktime: v.Ktime,
	}
	unix.Msg.Tuple = api.MsgIPTuple{
		IPv6:  k.Tuple.IPv6,
		SAddr: k.Tuple.SAddr,
		DAddr: k.Tuple.DAddr,
		SPort: k.Tuple.SPort,
		DPort: k.Tuple.DPort,
		Proto: 0,
	}
	unix.Msg.SockCookie = k.Cookie
	unix.Msg.Return = 0
	unix.Msg.ProcessKey = processapi.MsgExecveKey{
		Pid:   v.Pid,
		Ktime: v.PidKtime,
	}
	unix.Msg.SocketStats = api.MsgSocketStats{
		BytesSent:     v.TXBytes,
		BytesReceived: v.RXBytes,
		SegsIn:        uint32(v.SegsIn),
		SegsOut:       uint32(v.SegsOut),
		SkDrops:       v.SkDrops,
		Latency: api.Histogram{
			B00: v.Buckets[0],
			B01: v.Buckets[1],
			B10: v.Buckets[2],
			B25: v.Buckets[3],
			B50: v.Buckets[4],
			B75: v.Buckets[5],
			B90: v.Buckets[6],
			B99: v.Buckets[7],
			Sum: v.LatencySum,
		},
	}
	unix.Duration = duration
	return &unix
}

func createCloseEvent(k *api.UdpInfoKey, v *api.UdpInfoValue, closeTimeNs uint64) *layer3.MsgIPWithStatsEventUnix {
	var duration time.Duration
	if closeTimeNs > v.CreateTime {
		duration = time.Duration(closeTimeNs - v.CreateTime)
	} else {
		duration = 0
	}
	unix := createUdpStatsEvent(k, v, duration)
	unix.Msg.Common.Op = ops.MSG_OP_UDPCLOSE

	return unix
}

func emitCloseEvent(k *api.UdpInfoKey, v *api.UdpInfoValue) {
	currentTime := unix.Timespec{}
	closeTimeNs := uint64(0)
	err := unix.ClockGettime(int32(unix.CLOCK_MONOTONIC), &currentTime)
	if err == nil {
		closeTimeNs = uint64(currentTime.Nano())
	}

	unix := createCloseEvent(k, v, closeTimeNs)

	observer.AllListeners(unix)
}

func createStatEvent(k *api.UdpInfoKey, v *api.UdpInfoValue) *layer3.MsgIPWithStatsEventUnix {
	unix := createUdpStatsEvent(k, v, 0)
	unix.Msg.Common.Op = ops.MSG_OP_UDPSTATS

	return unix
}

func emitStatEvent(k *api.UdpInfoKey, v *api.UdpInfoValue) {
	unix := createStatEvent(k, v)

	if DisableStatsEvents {
		layer3.CreateProcessSockStats(unix, false)
	} else {
		observer.AllListeners(unix)
	}
}

func latencyResetEvent(curr, last *[8]uint64, currSum, lastSum uint64) bool {
	if curr[0] < last[0] ||
		curr[1] < last[1] ||
		curr[2] < last[2] ||
		curr[3] < last[3] ||
		curr[4] < last[4] ||
		curr[5] < last[5] ||
		curr[6] < last[6] ||
		curr[7] < last[7] ||
		currSum < lastSum {
		return true
	}
	return false
}

func udpResetEvent(curr, last *api.UdpInfoValue) bool {
	// If we have fewer bytes or segs than last measurement this is a
	// sure sign we had a data race. Counters in BPF side are monotonic
	// so a single entry will never be decrementing.
	if curr.SegsIn < last.SegsIn ||
		curr.RXBytes < last.RXBytes ||
		curr.SegsOut < last.SegsOut ||
		curr.TXBytes < last.TXBytes ||
		latencyResetEvent(&curr.Buckets, &last.Buckets, curr.LatencySum, last.LatencySum) {
		return true
	}

	// Its tempting to do a check here to test if the segs are the
	// same, but with different byte counts. The idea being bytes
	// can't appear without a segs inc as well. However, because
	// walker might read partial status of an update its possible
	// in the normal case for this so we can't use this test to
	// indicate a data race happened.
	//
	// Unfortunately what we can't learn is if datapath replaces
	// an old entry with a valid new entry. At which point we will
	// incorrectly diff the entry instead of add the entire value.
	// Hopefully this is rare and experiments show this to be the
	// case. Also note its more common on RX than TX because TX is
	// sender side and would mean application is submitting multiple
	// syscall sends on the same socket where as RX can be triggered
	// by receiving multiple packets on the same socket on the same
	// core.
	return false
}

func udpDiffLatency(last, curr *[8]uint64) [8]uint64 {
	return [8]uint64{
		curr[0] - last[0],
		curr[1] - last[1],
		curr[2] - last[2],
		curr[3] - last[3],
		curr[4] - last[4],
		curr[5] - last[5],
		curr[6] - last[6],
		curr[7] - last[7],
	}
}

func udpDiffValues(key *api.UdpInfoKey, last, curr *api.UdpInfoValue) (api.UdpInfoValue, error) {
	// The ktime check is to handle a small but observed race condition where
	// we can read a ktime earlier than a ktime we just read. It requires some
	// unlucky timing but here we go.
	//
	//  cpu0                      cpu1                    cpu2
	// 1 <- ktime_get_ns()
	//                         2 <- ktime_get_ns
	//                         v->ktime = 2
	//                                                 v2 <- read_map_key()
	//  v->ktime = 1
	//                                                 v1 <- read_map_key()
	//
	// and violla time travel from read map side. So just skip these entries
	// using v2 and because we have atomic only incrementing counters we
	// eventually we get a good entry and correct for any bytes at that time.
	if curr.Ktime < last.Ktime {
		return api.UdpInfoValue{}, fmt.Errorf("UDP Skip OOO Event")
	}

	// Test if this curr and last pair indicate a race condition in the
	// datapath caused a map_value to replace the last entry. In this case
	// to avoid dropping bytes on the counter we do not diff the values.
	if udpResetEvent(curr, last) {
		ipDst := api.GetIP(key.Tuple.DAddr, ops.MSG_OP_UDPSTATS, key.Tuple.IPv6 != 0)
		ipSrc := api.GetIP(key.Tuple.SAddr, ops.MSG_OP_UDPSTATS, key.Tuple.IPv6 != 0)
		logger.GetLogger().WithFields(logrus.Fields{"source": ipSrc, "dest": ipDst, "curr": curr, "last": last, "key": key,
			"pid": curr.Pid, "pidktime": curr.PidKtime}).Warnf("UDP stats underflow")
		return api.UdpInfoValue{}, fmt.Errorf("UDP stats invalid diff operation")
	}

	return api.UdpInfoValue{
		TXBytes:    curr.TXBytes - last.TXBytes,
		RXBytes:    curr.RXBytes - last.RXBytes,
		SegsIn:     curr.SegsIn - last.SegsIn,
		SegsOut:    curr.SegsOut - last.SegsOut,
		SkDrops:    curr.SkDrops - last.SkDrops,
		Ktime:      curr.Ktime,
		PidKtime:   curr.PidKtime,
		Pid:        curr.Pid,
		Buckets:    udpDiffLatency(&last.Buckets, &curr.Buckets),
		LatencySum: curr.LatencySum - last.LatencySum,
	}, nil
}

var (
	deleteLastKey *api.UdpInfoKey
)

func deleteLast(m *ebpf.Map) {
	if deleteLastKey != nil {
		if err := m.Delete(deleteLastKey); err != nil {
			logger.GetLogger().WithError(err).WithField("key", deleteLastKey).Warn("UDP delete key failed.")
			socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDeleteKeyFailed)
		}
		deleteLastKey = nil
	}
}

func udpGcCb(m *ebpf.Map, udpKey *api.UdpInfoKey, udpValue *api.UdpInfoValue) {
	// Access to TypeTotalRetrieve metrics is serialized by UdpGC.
	socketmetrics.UDPGCMetricIncNoLock(socketmetrics.UDPGCTypeTotalRetrieve)

	// If we delete the key out from under the walker it can't find the
	// next key and the result is we start walking from the first element
	// again. Giving us something like O(n!) for walking a list with lots
	// of deletes.
	deleteLast(m)

	t, err := ktime.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("time", udpValue.Ktime).Warn("UDP NanoTimeSince failed.")
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeNanoTimeSinceFailure)
		return
	}

	// Create a stats key that is the udpKey plus the pseudo-socket version.
	udpStatsKey := udpStatsKey{
		Cookie:    udpKey.Cookie,
		Tuple:     udpKey.Tuple,
		Version:   udpKey.Version,
		PsVersion: udpValue.PsVersion,
	}

	// This case handles kernels <5.10 where map will have udp stats
	// that are not yet associated to a process between IP stack and
	// socket handling of the UDP data.
	if udpValue.Pid == 0 {
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypePidIsZero)
	} else {
		if udpStatsEnable {
			last, ok := stats.Get(udpStatsKey)
			if ok {
				if *udpValue != last {
					diffValue, err := udpDiffValues(udpKey, &last, udpValue)
					if err == nil {
						stats.Add(udpStatsKey, *udpValue)
						emitStatEvent(udpKey, &diffValue)
					} else {
						socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailureGC)
					}
				}
			} else {
				stats.Add(udpStatsKey, *udpValue)
				emitStatEvent(udpKey, udpValue)
			}
		}
	}

	if t > UdpDeleteInterval {
		if udpValue.Pid != 0 && !DisableCloseEvents {
			emitCloseEvent(udpKey, udpValue)
		}
		stats.Remove(udpStatsKey)
		pseudoSocketsUpdate.Lock()
		pseudoKey := cookieVer{Cookie: udpKey.Cookie, Version: udpKey.Version}
		if pseudoSockets[pseudoKey] != nil {
			delete(pseudoSockets[pseudoKey], udpPseudoSocket{SAddr: udpKey.Tuple.SAddr, SPort: udpKey.Tuple.SPort,
				DAddr: udpKey.Tuple.DAddr, DPort: udpKey.Tuple.DPort, IPv6: udpKey.Tuple.IPv6, PsVersion: udpValue.PsVersion})
		}
		pseudoSocketsUpdate.Unlock()
		deleteLastKey = udpKey.Copy()
	}
}

func runUdpGC() {
	// Access to UDPGCTypeTicker is serialized by UdpGC
	socketmetrics.UDPGCMetricIncNoLock(socketmetrics.UDPGCTypeTicker)

	file := filepath.Join(bpf.MapPrefixPath(), UdpMapName)

	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("UDP GC failed to open file")
		// lock is safe only done here inside GC
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeFailedToOpenMap)
		return
	}
	defer m.Close()

	var (
		key api.UdpInfoKey
		val api.UdpInfoValue
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		udpGcCb(m, &key, &val)
	}
	// Check if the last key needed deleting
	deleteLast(m)
}
