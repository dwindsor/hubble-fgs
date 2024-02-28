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
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/sirupsen/logrus"
)

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

var (
	gcTimer    = timer.NewPeriodicTimer("TCP GC Timer", runTcpGC, true)
	TcpMapName = "tg_socket_map"
)

func emitStatEvent(k *tcpKey, v *tcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats) {
	unix := layer3.MsgIPWithStatsEventUnix{}
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
	tuple := value.ToMsgIpTuple()
	tcpStats := value.ToMsgSocketStatsUnix()
	statsKey := tcpKey{SockCookie: key.SockCookie, CreateTime: value.CreateTime}

	// This case handles kernels <5.10 where map will have udp stats
	// that are not yet associated to a process between IP stack and
	// socket handling of the UDP data.
	if value.Key.Pid == 0 {
		return
	} else if tuple.Proto == IPPROTO_TCP {
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

func configureSockStatSampler(sampleRate time.Duration, watermarksEnable bool, watermarksAvgWindowSize uint64,
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
