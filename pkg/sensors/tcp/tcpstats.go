package tcp

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

type SockStatKey struct {
	Zero uint32
}

func (k *SockStatKey) String() string             { return fmt.Sprintf("Zero: %d", k.Zero) }
func (k *SockStatKey) NewValue() bpf.MapValue     { return &SockStatValue{} }
func (k *SockStatKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *SockStatKey) DeepCopyMapKey() bpf.MapKey { return &SockStatKey{} }

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
func (v *SockStatValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SockStatValue) DeepCopyMapValue() bpf.MapValue {
	return &SockStatValue{}
}

func configureSockStatSampler(sampleRate time.Duration, watermarksEnable bool, watermarksAvgWindowSize uint64,
	burstTriggerMult uint64, dipTriggerMult uint64, rttMax, rttMin uint32) error {
	m, err := bpf.OpenMap(filepath.Join(bpf.MapPrefixPath(), SendCheckSampler.Name))
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
	m.Update(key, value)
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
	return nil
}
