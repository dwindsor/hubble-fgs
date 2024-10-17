//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpCache"
	"github.com/sirupsen/logrus"
)

var (
	gcTimer    = timer.NewPeriodicTimer("TCP GC Timer", getRunTcpGC(emitSocketStatsEvent), true)
	TcpMapName = "tg_tcpsocket_map"
)

type collectKeyFn func(*networkapi.TcpBpfKey, *networkapi.TcpValue)
type emitStatsFn func(k *networkapi.TcpKey, v *networkapi.TcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats)

type SockStatKey struct {
	Zero uint32
}

func (k *SockStatKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

type SockStatValue struct {
	WatermarksEnable           uint64
	WatermarksAvgWindowSize    uint64
	WatermarksWindowSizeNs     uint64
	WatermarksBurstTriggerMult uint64
	WatermarksDipTriggerMult   uint64
	RttBucket0                 uint32
	RttBucket1                 uint32
	RttBucket2                 uint32
	RttBucket3                 uint32
	RttBucket4                 uint32
	RttBucket5                 uint32
	RttBucket6                 uint32
	RttBucket7                 uint32
}

func (v *SockStatValue) String() string {
	return fmt.Sprintf(
		"WatermarksEnable: %d, "+
			"WatermarksAvgWindowSize: %d, "+
			"WatermarksWindowSizeNs: %d, "+
			"WatermarksBurstTriggerMult: %d, "+
			"WatermarksDipTriggerMult: %d",
		v.WatermarksEnable, v.WatermarksAvgWindowSize, v.WatermarksWindowSizeNs, v.WatermarksBurstTriggerMult, v.WatermarksDipTriggerMult)
}

func socketStatsToIPWithStatsEventUnix(k *networkapi.TcpKey, v *networkapi.TcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats) *grpc.MsgIPWithStatsEventUnix {
	unix := grpc.MsgIPWithStatsEventUnix{}
	unix.Msg = &networkapi.MsgIPWithStatsEvent{}

	unix.Msg.Common = processapi.MsgCommon{
		Op:    ops.MSG_OP_TCPSTATS,
		Size:  1,
		Ktime: stats.Ktime,
	}
	unix.Msg.Tuple = *tuple
	unix.Msg.SockCookie = k.SockCookie
	unix.Msg.Return = 0
	unix.Msg.ProcessKey = processapi.MsgExecveKey{
		Pid:   v.Key.Pid,
		Ktime: v.Key.Ktime,
	}
	unix.Msg.Common.Flags = 0
	unix.Msg.SocketStats = *stats
	unix.Duration = 0

	return &unix
}

func emitSocketStatsEvent(k *networkapi.TcpKey, v *networkapi.TcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats) {
	observer.AllListeners(socketStatsToIPWithStatsEventUnix(k, v, tuple, stats))
}

func getTCPGCCallback(emitStats emitStatsFn) collectKeyFn {
	return func(key *networkapi.TcpBpfKey, value *networkapi.TcpValue) {
		// We don't need to account further if the socket has already been closed.
		if value.Closed != 0 {
			return
		}
		tuple := tcpCache.GetTuple(key.SockCookie, value.Version)
		tcpStats := ToMsgSocketStatsUnix(value)
		statsKey := networkapi.TcpKey{SockCookie: key.SockCookie, CreateTime: value.Stats.CreateTime}

		last, ok := stats.Get(statsKey)
		if ok {
			// If Ktime is the same as last read then nothing has changed.
			if tcpStats.Ktime != last.Ktime {
				diffValue, err := tcpDiffValues(&last, tcpStats, tuple)
				// Store the stats from the BPF map into the cache
				stats.Add(statsKey, *tcpStats)
				if err == nil {
					emitStats(&statsKey, value, tuple, &diffValue)
				} else {
					logger.GetLogger().WithError(err).Warn("TCP statistics tcpDiffValues")
				}
			}
		} else {
			emitStats(&statsKey, value, tuple, tcpStats)
			stats.Add(statsKey, *tcpStats)
		}
	}
}

func getRunTcpGC(emitStats emitStatsFn) func() {
	callback := getTCPGCCallback(emitStats)
	return func() {
		file := filepath.Join(bpf.MapPrefixPath(), TcpMapName)

		m, err := ebpf.LoadPinnedMap(file, nil)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("file", file).Warn("TCP GC failed to open file")
			return
		}
		defer m.Close()

		var (
			key networkapi.TcpBpfKey
			val networkapi.TcpValue
		)

		iter := m.Iterate()
		for iter.Next(&key, &val) {
			callback(&key, &val)
		}
	}
}

func ToMsgSocketStatsUnix(t *networkapi.TcpValue) *networkapi.MsgSocketStats {
	s := &networkapi.MsgSocketStats{}
	s.Ktime = t.Stats.Ktime
	s.CreateTime = t.Stats.CreateTime
	s.BytesSent = t.Stats.BytesSent
	s.BytesReceived = t.Stats.BytesReceived - uint64(t.FinRx)
	s.SegsIn = t.Stats.SegsIn
	s.SegsOut = t.Stats.SegsOut
	s.Srtt = t.Stats.Srtt
	s.RetransmitSegs = t.Stats.RetransmitSegs
	s.RetransmitBytes = t.Stats.RetransmitBytes
	s.ZeroWindow = t.Stats.ZeroWindow
	s.SkDrops = t.Stats.SkDrops

	s.Rtt = t.Stats.Rtt
	s.Latency = t.Stats.Latency

	return s
}

func tcpDiffHistogram(last, curr *networkapi.Histogram, ty, source, dest string) (networkapi.Histogram, error) {
	if curr.B99 < last.B99 ||
		curr.B90 < last.B90 ||
		curr.B75 < last.B75 ||
		curr.B50 < last.B50 ||
		curr.B25 < last.B25 ||
		curr.B10 < last.B10 ||
		curr.B01 < last.B01 ||
		curr.B00 < last.B00 ||
		curr.Sum < last.Sum {
		logger.GetLogger().WithFields(logrus.Fields{"source": source, "dest": dest, "curr": curr, "last": last}).Warnf("TCP %s stats underflow", ty)
		return networkapi.Histogram{}, fmt.Errorf("TCP %s stats invalid diff operation", ty)
	}
	return networkapi.Histogram{
		B99: curr.B99 - last.B99,
		B90: curr.B90 - last.B90,
		B75: curr.B75 - last.B75,
		B50: curr.B50 - last.B50,
		B25: curr.B25 - last.B25,
		B10: curr.B10 - last.B10,
		B01: curr.B01 - last.B01,
		B00: curr.B00 - last.B00,
		Sum: curr.Sum - last.Sum,
	}, nil
}

func tcpDiffValues(last, curr *networkapi.MsgSocketStats, tuple *networkapi.MsgIPTuple) (networkapi.MsgSocketStats, error) {
	source, dest := networkapi.TupleAddrString(tuple, ops.MSG_OP_TCPSTATS)
	if curr.BytesReceived < last.BytesReceived {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("RX TCP stats received bytes underflow")
		return *last, fmt.Errorf("TCP BytesReceived stats invalid diff operation")
	}
	if curr.BytesSent < last.BytesSent {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("TX TCP stats sent bytes underflow")
		return *last, fmt.Errorf("TCP BytesSent stats invalid diff operation")
	}
	if curr.SegsIn < last.SegsIn {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("RX TCP stats SegsIn underflow")
		return *last, fmt.Errorf("TCP SegsIn stats invalid diff operation")
	}
	if curr.SegsOut < last.SegsOut {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("TX TCP stats SegsOut underflow")
		return *last, fmt.Errorf("TCP SegsOut stats invalid diff operation")
	}
	if curr.SkDrops < last.SkDrops {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("TX TCP stats SkDrop underflow")
		return *last, fmt.Errorf("TCP SkDrop stats invalid diff operation")
	}

	rttHist, err := tcpDiffHistogram(&last.Rtt, &curr.Rtt, "RTT", source, dest)
	if err != nil {
		return *last, err
	}
	latencyHist, err := tcpDiffHistogram(&last.Latency, &curr.Latency, "Latency", source, dest)
	if err != nil {
		return *last, err
	}
	return networkapi.MsgSocketStats{
		Ktime:           curr.Ktime,
		BytesSent:       curr.BytesSent - last.BytesSent,
		BytesReceived:   curr.BytesReceived - last.BytesReceived,
		SegsIn:          curr.SegsIn - last.SegsIn,
		SegsOut:         curr.SegsOut - last.SegsOut,
		Srtt:            curr.Srtt,
		RetransmitSegs:  curr.RetransmitSegs - last.RetransmitSegs,
		RetransmitBytes: curr.RetransmitBytes - last.RetransmitBytes,
		ZeroWindow:      curr.ZeroWindow - last.ZeroWindow,
		SkDrops:         curr.SkDrops - last.SkDrops,
		Rtt:             rttHist,
		Latency:         latencyHist,
		CreateTime:      curr.CreateTime,
	}, nil
}

func copyMsgIpWithStatsEvent(tcp *grpc.MsgIPWithStatsEventUnix) grpc.MsgIPWithStatsEventUnix {
	newTcp := *tcp
	newMsg := *tcp.Msg
	newTcp.Msg = &newMsg
	return newTcp
}

// There is a race condition where two events are sent from BPF side in close
// proximity time wise to each other. In this case its possible to process the
// events out of order. Specifically it means when we diff the events the 'last'
// event in cache will have a newer time than the 'new' event from BPF side. If
// this happens discard the older event.
func correctedStatsEvent(tcp grpc.MsgIPWithStatsEventUnix) (grpc.MsgIPWithStatsEventUnix, error) {
	statsKey := networkapi.TcpKey{SockCookie: tcp.Msg.SockCookie, CreateTime: tcp.Msg.SocketStats.CreateTime}
	last, ok := stats.Get(statsKey)
	if !ok {
		return copyMsgIpWithStatsEvent(&tcp), nil
	}
	if tcp.Msg.SocketStats.Ktime < last.Ktime {
		// Current stats message is older than last stats message.
		// This indicates the race has occurred, so we discard.
		return grpc.MsgIPWithStatsEventUnix{}, fmt.Errorf("TCP stats message is older than previous")
	}

	// If we already posted an entry and nothings changed skip it.
	if tcp.Msg.SocketStats.Ktime == last.Ktime {
		return grpc.MsgIPWithStatsEventUnix{}, fmt.Errorf("TCP stats message duplicate")
	}

	tmpSocketStats, err := tcpDiffValues(&last, &tcp.Msg.SocketStats, &tcp.Msg.Tuple)
	if err != nil {
		return grpc.MsgIPWithStatsEventUnix{}, err
	}
	newTcp := copyMsgIpWithStatsEvent(&tcp)
	stats.Add(statsKey, tcp.Msg.SocketStats)
	newTcp.Msg.SocketStats = tmpSocketStats
	return newTcp, nil
}

func ConfigureSockStatSampler(sampleRate time.Duration, watermarksEnable bool, watermarksAvgWindowSize uint64,
	burstTriggerMult uint64, dipTriggerMult uint64, rttMax, rttMin uint32) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), SendCheckSampler.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &SockStatKey{
		Zero: uint32(0),
	}

	watermarksEnableVar := uint64(0)
	if watermarksEnable {
		watermarksEnableVar = 1
	}

	rttRange := float64(rttMax - rttMin)
	fRttMin := float64(rttMin)

	value := &SockStatValue{
		WatermarksEnable:           watermarksEnableVar,
		WatermarksAvgWindowSize:    watermarksAvgWindowSize,
		WatermarksWindowSizeNs:     (watermarksAvgWindowSize * 2 * 1000000) / 3,
		WatermarksBurstTriggerMult: burstTriggerMult + 100,
		WatermarksDipTriggerMult:   100 - dipTriggerMult,
		RttBucket0:                 rttMin,
		RttBucket1:                 uint32((rttRange * .01) + fRttMin),
		RttBucket2:                 uint32((rttRange * .10) + fRttMin),
		RttBucket3:                 uint32((rttRange * .25) + fRttMin),
		RttBucket4:                 uint32((rttRange * .50) + fRttMin),
		RttBucket5:                 uint32((rttRange * .75) + fRttMin),
		RttBucket6:                 uint32((rttRange * .90) + fRttMin),
		RttBucket7:                 uint32((rttRange * .99) + fRttMin),
	}
	m.Put(key, value)
	logger.GetLogger().WithField("time", sampleRate).Info("Configured TCP sock statistic sampler: ")
	logger.GetLogger().WithFields(logrus.Fields{"enable": watermarksEnable,
		"windowSize":       watermarksAvgWindowSize,
		"burstTriggerMult": burstTriggerMult,
		"dipTriggerMult":   dipTriggerMult,
	}).Info("Configured TCP watermarks: ")
	logger.GetLogger().WithFields(logrus.Fields{"rttMin": rttMin, "rttRange": rttRange,
		"bucket0": value.RttBucket0,
		"bucket1": value.RttBucket1,
		"bucket2": value.RttBucket2,
		"bucket3": value.RttBucket3,
		"bucket4": value.RttBucket4,
		"bucket5": value.RttBucket5,
		"bucket6": value.RttBucket6,
		"bucket7": value.RttBucket7}).Info("Configured RTT buckets: ")

	// Configure the TCP stats collector that walks the TCP BPF map every
	// time.Durations and post statistics about that connections. This is
	// to ensure long lived connections get metrics and SIEM updates.
	gcTimer.Start(sampleRate)

	return nil
}
