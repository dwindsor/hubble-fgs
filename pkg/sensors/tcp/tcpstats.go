package tcp

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

type SockStatKey struct {
	Zero uint32
}

func (k *SockStatKey) String() string             { return fmt.Sprintf("Zero: %d", k.Zero) }
func (k *SockStatKey) NewValue() bpf.MapValue     { return &SockStatValue{} }
func (k *SockStatKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *SockStatKey) DeepCopyMapKey() bpf.MapKey { return &SockStatKey{} }

type SockStatValue struct {
	KTime uint64
}

func (v *SockStatValue) String() string {
	return fmt.Sprintf("Sample Time: %d", v.KTime)
}
func (v *SockStatValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SockStatValue) DeepCopyMapValue() bpf.MapValue {
	return &SockStatValue{}
}

func configureSockStatSampler(sampleRate time.Duration) error {
	m, err := bpf.OpenMap(filepath.Join(sensors.MapDir, TCPSendCheckSampler.Name))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &SockStatKey{
		Zero: uint32(0),
	}
	interval := uint64(sampleRate)
	/* Convert sample rate from seconds into ns */
	value := &SockStatValue{
		KTime: interval,
	}
	m.Update(key, value)
	logger.GetLogger().WithField("time", sampleRate).Info("Configured TCP sock statistic sampler: ")
	return nil
}
