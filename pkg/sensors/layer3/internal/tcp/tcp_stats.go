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
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/timer"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/sirupsen/logrus"
)

const (
	TcpMapName     = "tg_tcpsocket_map"
	statsCacheSize = 32000
)

type collectFn func()
type collectKeyFn func(*networkapi.TcpBpfKey, *networkapi.TcpValue)
type emitStatsFn func(k *networkapi.TcpKey, v *networkapi.TcpValue, stats *networkapi.MsgSocketStats)

type statsManager struct {
	// getCollect returns a function that will be executed on a timer,
	// for capturing cache.
	getCollect func(*lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) collectFn
	cache      *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]
	timer      *timer.PeriodicTimer
}

func (s *statsManager) enable(interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be > 0, got %v", interval)
	}

	var err error
	s.cache, err = lru.New[networkapi.TcpKey, networkapi.MsgSocketStats](statsCacheSize)
	if err != nil || s.cache == nil {
		return fmt.Errorf("failed to create a cache: %w", err)
	}

	s.timer = timer.NewPeriodicTimer("TCP stats timer", s.getCollect(s.cache), false)
	s.timer.Start(interval)

	return nil
}

func (s *statsManager) disable() {
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.cache != nil {
		s.cache.Purge()
	}
}

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

func socketStatsToIPWithStatsEventUnix(k *networkapi.TcpKey, v *networkapi.TcpValue, stats *networkapi.MsgSocketStats) *grpc.MsgIPWithStatsEventUnix {
	unix := grpc.MsgIPWithStatsEventUnix{}
	unix.Msg = &networkapi.MsgIPWithStatsEvent{}

	unix.Msg.Common = processapi.MsgCommon{
		Op:    ops.MSG_OP_TCPSTATS,
		Size:  1,
		Ktime: stats.Ktime,
	}
	unix.Msg.Tuple = v.Tuple
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

func emitSocketStatsEvent(k *networkapi.TcpKey, v *networkapi.TcpValue, stats *networkapi.MsgSocketStats) {
	observer.AllListeners(socketStatsToIPWithStatsEventUnix(k, v, stats))
}

func getTCPGCCallback(emitStats emitStatsFn, cache *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) collectKeyFn {
	return func(key *networkapi.TcpBpfKey, value *networkapi.TcpValue) {
		// We don't need to account further if the socket has already been closed.
		if value.Closed != 0 {
			return
		}
		tcpStats := &value.Stats
		statsKey := networkapi.TcpKey{SockCookie: key.SockCookie, CreateTime: value.Stats.CreateTime}

		last, ok := cache.Get(statsKey)

		// Explicit check for underflowed bytes_received < 0
		if int64(tcpStats.BytesReceived) < 0 {
			logger.GetLogger().WithFields(logrus.Fields{
				"curr":          tcpStats,
				"last":          last,
				"cookie":        key.SockCookie,
				"version":       value.Version,
				"socketFlags":   value.SocketFlags,
				"bytesReceived": int64(tcpStats.BytesReceived),
			}).Warn("TCP stats underflow in bytesReceived in stats GC")
			// Correct it to make stats/metrics more sane (but beware that the bug still needs fixing
			// as it likely affects sockets where bytes_received wasn't 0 before the decrement)
			tcpStats.BytesReceived = 0
		}

		if ok {
			// If Ktime is the same as last read then nothing has changed.
			if tcpStats.Ktime != last.Ktime {
				diffValue, err := tcpDiffValues(&last, tcpStats)
				// Store the stats from the BPF map into the cache
				cache.Add(statsKey, *tcpStats)
				if err == nil {
					emitStats(&statsKey, value, &diffValue)
				} else {
					logger.GetLogger().WithError(err).WithFields(logrus.Fields{
						"curr":        tcpStats,
						"last":        last,
						"cookie":      key.SockCookie,
						"version":     value.Version,
						"socketFlags": value.SocketFlags,
					}).Warn("Failed to compute diff for TCP stats")
				}
			}
		} else {
			emitStats(&statsKey, value, tcpStats)
			cache.Add(statsKey, *tcpStats)
		}
	}
}

func getRunTcpGC(emitStats emitStatsFn, cache *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) func() {
	callback := getTCPGCCallback(emitStats, cache)
	return func() {
		file := filepath.Join(bpf.MapPrefixPath(), TcpMapName)

		m, err := ebpf.LoadPinnedMap(file, nil)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("file", file).Debug("TCP GC failed to open file")
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
	s.BytesReceived = t.Stats.BytesReceived
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

func tcpDiffHistogram(last, curr *networkapi.Histogram, ty string) (networkapi.Histogram, error) {
	if curr.B99 < last.B99 ||
		curr.B90 < last.B90 ||
		curr.B75 < last.B75 ||
		curr.B50 < last.B50 ||
		curr.B25 < last.B25 ||
		curr.B10 < last.B10 ||
		curr.B01 < last.B01 ||
		curr.B00 < last.B00 ||
		curr.Sum < last.Sum {
		return networkapi.Histogram{}, fmt.Errorf("current %s histogram buckets < last", ty)
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

func tcpDiffValues(last, curr *networkapi.MsgSocketStats) (networkapi.MsgSocketStats, error) {
	var joinedErr error
	if curr.BytesReceived < last.BytesReceived {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("current BytesReceived < last"))
	}
	if curr.BytesSent < last.BytesSent {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("current BytesSent < last"))
	}
	if curr.SegsIn < last.SegsIn {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("current SegsIn < last"))
	}
	if curr.SegsOut < last.SegsOut {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("current SegsOut < last"))
	}
	if curr.SkDrops < last.SkDrops {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("current SkDrops < last"))
	}

	rttHist, err := tcpDiffHistogram(&last.Rtt, &curr.Rtt, "RTT")
	if err != nil {
		joinedErr = errors.Join(joinedErr, err)
	}
	latencyHist, err := tcpDiffHistogram(&last.Latency, &curr.Latency, "Latency")
	if err != nil {
		joinedErr = errors.Join(joinedErr, err)
	}

	if joinedErr != nil {
		return *last, joinedErr
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
func (s *statsManager) correctedStatsEvent(tcp grpc.MsgIPWithStatsEventUnix) (grpc.MsgIPWithStatsEventUnix, error) {
	newTcp := copyMsgIpWithStatsEvent(&tcp)
	if s.cache == nil {
		return newTcp, nil
	}
	statsKey := networkapi.TcpKey{SockCookie: tcp.Msg.SockCookie, CreateTime: tcp.Msg.SocketStats.CreateTime}
	last, ok := s.cache.Get(statsKey)
	if !ok {
		return newTcp, nil
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

	tmpSocketStats, err := tcpDiffValues(&last, &tcp.Msg.SocketStats)
	if err != nil {
		return grpc.MsgIPWithStatsEventUnix{}, err
	}

	s.cache.Add(statsKey, tcp.Msg.SocketStats)
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
	if err := stats.enable(sampleRate); err != nil {
		return fmt.Errorf("failed to enable TCP stats events: %w", err)
	}

	return nil
}
