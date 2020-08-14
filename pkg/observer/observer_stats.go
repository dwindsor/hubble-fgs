package observer

import (
	"fmt"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
)

type statKey struct {
	Key int32
}

type statValue struct {
	Value [64]int32
}

func (k *statKey) String() string             { return fmt.Sprintf("key=%d", k.Key) }
func (k *statKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *statKey) NewValue() bpf.MapValue     { return &statValue{} }
func (k *statKey) DeepCopyMapKey() bpf.MapKey { return &statKey{k.Key} }

func (s *statValue) String() string                 { return fmt.Sprintf("value=%d", s.Value) }
func (s *statValue) GetValuePtr() unsafe.Pointer    { return unsafe.Pointer(s) }
func (s *statValue) DeepCopyMapValue() bpf.MapValue { return &statValue{s.Value} }

func (k *ObserverKprobe) startUpdateMapMetrics() {
	update := func() {
		for _, m := range observerMaps {
			pin := k.mapDir + m.mapName
			pinStats := pin + "_stats"

			mapLinkStats, err := bpf.OpenMap(pinStats)
			if err != nil {
				continue
			}
			mapLink, err := bpf.OpenMap(pin)
			if err != nil {
				continue
			}

			zeroKey := &statKey{}
			value, err := mapLinkStats.Lookup(zeroKey)
			if err != nil {
				continue
			}

			v, ok := value.DeepCopyMapValue().(*statValue)
			if !ok {
				continue
			}
			sum := int32(0)
			for cpu := int(0); cpu < runtime.NumCPU(); cpu++ {
				sum += v.Value[cpu]
			}
			metrics.ExecveMapSize.WithLabelValues(m.mapName, strconv.Itoa(int(mapLink.MapInfo.MaxEntries))).Set(float64(sum))
			mapLink.Close()
			mapLinkStats.Close()
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				update()
			}
		}
	}()
}
