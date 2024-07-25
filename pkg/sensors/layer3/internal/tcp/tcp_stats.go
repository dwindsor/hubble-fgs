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
	gcTimer    = timer.NewPeriodicTimer("TCP GC Timer", runTcpGC, true)
	TcpMapName = "tg_tcpsocket_map"
)

type tcpBpfKey struct {
	SockCookie uint64
}

func (k *tcpBpfKey) String() string { return fmt.Sprintf("Cookie: %d", k.SockCookie) }

type tcpKey struct {
	SockCookie uint64
	CreateTime uint64
}

type tcpValue struct {
	Key             processapi.MsgExecveKey
	CreateTime      uint64
	ZeroWindow      uint32
	SocketFlags     uint32
	LastTime        uint64
	Sent            uint64
	Recv            uint64
	SegsOut         uint32
	SegsIn          uint32
	RetransmitBytes uint64
	RetransmitSegs  uint32
	SkDrops         uint32
	Srtt            uint32
	Version         uint32
	RttBuckets      [8]uint64
	LatencyBuckets  [8]uint64
	FinRx           uint8
	Protocol        uint8
	Pad             [6]uint8
	RttSum          uint64
	LatencySum      uint64
}

func (t *tcpValue) String() string {
	return fmt.Sprintf("Pid: %d CreateTime %d Last %d Sent (%d:%d) Recv (%d:%d) Zero %d Retransmit (%d:%d) Drops %d Srtt %d",
		t.Key.Pid,
		t.CreateTime, t.LastTime,
		t.Sent, t.SegsOut, t.Recv-uint64(t.FinRx), t.SegsIn,
		t.ZeroWindow,
		t.RetransmitBytes, t.RetransmitSegs,
		t.SkDrops, t.Srtt)
}

type SockStatKey struct {
	Zero uint32
}

func (k *SockStatKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

type SockStatValue struct {
	KTime                      uint64
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
	return fmt.Sprintf("Sample Time: %d, "+
		"WatermarksEnable: %d, "+
		"WatermarksAvgWindowSize: %d, "+
		"WatermarksWindowSizeNs: %d, "+
		"WatermarksBurstTriggerMult: %d, "+
		"WatermarksDipTriggerMult: %d",
		v.KTime, v.WatermarksEnable, v.WatermarksAvgWindowSize, v.WatermarksWindowSizeNs, v.WatermarksBurstTriggerMult, v.WatermarksDipTriggerMult)
}

func emitStatEvent(k *tcpKey, v *tcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats) {
	unix := grpc.MsgIPWithStatsEventUnix{}
	unix.Msg = &networkapi.MsgIPWithStatsEvent{}

	unix.Msg.Common = processapi.MsgCommon{
		Op:    ops.MsgOpTCPStats,
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

	observer.AllListeners(&unix)
}

func tcpGcCb(_ *ebpf.Map, key *tcpBpfKey, value *tcpValue) {
	tuple := tcpCache.GetTuple(key.SockCookie, value.Version)
	tcpStats := value.ToMsgSocketStatsUnix()
	statsKey := tcpKey{SockCookie: key.SockCookie, CreateTime: value.CreateTime}

	last, ok := stats.Get(statsKey)
	if ok {
		// If Ktime is the same as last read then nothing has changed.
		if tcpStats.Ktime != last.Ktime {
			diffValue, err := tcpDiffValues(&last, tcpStats, tuple)
			if err == nil {
				stats.Add(statsKey, *tcpStats)
				emitStatEvent(&statsKey, value, tuple, &diffValue)
			} else {
				logger.GetLogger().WithError(err).Warn("TCP statistics tcpDiffValues")
			}
		}
	} else {
		emitStatEvent(&statsKey, value, tuple, tcpStats)
		stats.Add(statsKey, *tcpStats)
	}
}

func runTcpGC() {
	file := filepath.Join(bpf.MapPrefixPath(), TcpMapName)

	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("TCP GC failed to open file")
		return
	}
	defer m.Close()

	var (
		key tcpBpfKey
		val tcpValue
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		tcpGcCb(m, &key, &val)
	}
}

func (t *tcpValue) ToMsgSocketStatsUnix() *networkapi.MsgSocketStats {
	s := &networkapi.MsgSocketStats{}
	s.Ktime = t.LastTime
	s.CreateKtime = t.CreateTime
	s.BytesSent = t.Sent
	s.BytesReceived = t.Recv - uint64(t.FinRx)
	s.SegsIn = t.SegsIn
	s.SegsOut = t.SegsOut
	s.BytesSubmitted = 0
	s.BytesConsumed = 0
	s.SegsConsumed = 0
	s.SegsSubmitted = 0
	s.SRtt = t.Srtt
	s.RetransmitSegs = t.RetransmitSegs
	s.RetransmitBytes = t.RetransmitBytes
	s.ToZeroWindow = t.ZeroWindow
	s.SkDrop = t.SkDrops
	s.SkbConsumeMisses = 0

	s.Rtt = networkapi.Histogram{
		B00: t.RttBuckets[0],
		B01: t.RttBuckets[1],
		B10: t.RttBuckets[2],
		B25: t.RttBuckets[3],
		B50: t.RttBuckets[4],
		B75: t.RttBuckets[5],
		B90: t.RttBuckets[6],
		B99: t.RttBuckets[7],
		Sum: t.RttSum,
	}

	s.Latency = networkapi.Histogram{
		B00: t.LatencyBuckets[0],
		B01: t.LatencyBuckets[1],
		B10: t.LatencyBuckets[2],
		B25: t.LatencyBuckets[3],
		B50: t.LatencyBuckets[4],
		B75: t.LatencyBuckets[5],
		B90: t.LatencyBuckets[6],
		B99: t.LatencyBuckets[7],
		Sum: t.LatencySum,
	}

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
	rttHist, err := tcpDiffHistogram(&last.Rtt, &curr.Rtt, "RTT", source, dest)
	if err != nil {
		return *last, err
	}
	latencyHist, err := tcpDiffHistogram(&last.Latency, &curr.Latency, "Latency", source, dest)
	if err != nil {
		return *last, err
	}
	return networkapi.MsgSocketStats{
		BytesSubmitted:   0,
		BytesSent:        curr.BytesSent - last.BytesSent,
		BytesConsumed:    0,
		BytesReceived:    curr.BytesReceived - last.BytesReceived,
		SegsConsumed:     0,
		SegsIn:           curr.SegsIn - last.SegsIn,
		SegsSubmitted:    0,
		SegsOut:          curr.SegsOut - last.SegsOut,
		SRtt:             curr.SRtt,
		RetransmitSegs:   curr.RetransmitSegs - last.RetransmitSegs,
		RetransmitBytes:  curr.RetransmitBytes - last.RetransmitBytes,
		ToZeroWindow:     curr.ToZeroWindow - last.ToZeroWindow,
		SkDrop:           curr.SkDrop - last.SkDrop,
		SkbConsumeMisses: 0,
		Rtt:              rttHist,
		Latency:          latencyHist,
		CreateKtime:      curr.CreateKtime,
	}, nil
}

// There is a race condition where two events are sent from BPF side in close
// proximity time wise to each other. In this case its possible to process the
// events out of order. Specifically it means when we diff the events the 'last'
// event in cache will have a newer time than the 'new' event from BPF side. If
// this happens discard the older event.
func correctedStatsEvent(tcp grpc.MsgIPWithStatsEventUnix) (grpc.MsgIPWithStatsEventUnix, error) {
	statsKey := tcpKey{SockCookie: tcp.Msg.SockCookie, CreateTime: tcp.Msg.SocketStats.CreateKtime}
	last, ok := stats.Get(statsKey)
	if !ok {
		return tcp, nil
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
	// Make a copy of the event
	newTcp := tcp
	// Make a copy of the referenced Msg
	newMsg := *tcp.Msg
	newTcp.Msg = &newMsg
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
	interval := uint64(sampleRate)
	watermarksEnableVar := uint64(0)
	if watermarksEnable {
		watermarksEnableVar = 1
	}

	rttRange := float64(rttMax - rttMin)
	fRttMin := float64(rttMin)

	/* Convert sample rate from seconds into ns */
	value := &SockStatValue{
		KTime:                      interval,
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
