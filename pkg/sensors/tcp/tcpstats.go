package tcp

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/logger"
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
	KTime              uint64
	BurstEnable        uint64
	BurstAvgWindowSize uint64
	BurstWindowSizeNs  uint64
	BurstTriggerMult   uint64
}

func (v *SockStatValue) String() string {
	return fmt.Sprintf("Sample Time: %d, "+
		"BurstEnable: %d, "+
		"BurstAvgWindowSize: %d, "+
		"BurstWindowSizeNs: %d, "+
		"BurstTriggerMult: %d, ",
		v.KTime, v.BurstEnable, v.BurstAvgWindowSize, v.BurstWindowSizeNs, v.BurstTriggerMult)
}
func (v *SockStatValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SockStatValue) DeepCopyMapValue() bpf.MapValue {
	return &SockStatValue{}
}

func configureSockStatSampler(sampleRate time.Duration, burstEnable bool, burstAvgWindowSize uint64,
	burstTriggerMult uint64) error {
	m, err := bpf.OpenMap(filepath.Join(bpf.MapPrefixPath(), TCPSendCheckSampler.Name))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &SockStatKey{
		Zero: uint32(0),
	}
	interval := uint64(sampleRate)
	burstEnableVar := uint64(0)
	if burstEnable {
		burstEnableVar = 1
	}
	/* Convert sample rate from seconds into ns */
	value := &SockStatValue{
		KTime:              interval,
		BurstEnable:        burstEnableVar,
		BurstAvgWindowSize: burstAvgWindowSize,
		BurstWindowSizeNs:  (burstAvgWindowSize * 2 * 1000000) / 3,
		BurstTriggerMult:   burstTriggerMult + 100,
	}
	m.Update(key, value)
	logger.GetLogger().WithField("time", sampleRate).Info("Configured TCP sock statistic sampler: ")
	logger.GetLogger().WithFields(logrus.Fields{"enable": burstEnable,
		"windowSize":  burstAvgWindowSize,
		"triggerMult": burstTriggerMult}).Info("Configured TCP watermarks: ")
	return nil
}
