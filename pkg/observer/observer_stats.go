//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

type statKey struct {
	Key int32
}

type statValue struct {
	Value []int64 // kernel rounds up to 64bits so pretend its a 64bit here
}

func (k *statKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *statKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *statKey) NewValue() bpf.MapValue {
	return &statValue{
		Value: make([]int64, runtime.NumCPU()),
	}
}
func (k *statKey) DeepCopyMapKey() bpf.MapKey { return &statKey{k.Key} }

func (s *statValue) String() string {
	return fmt.Sprintf("%v", s.Value)
}
func (s *statValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&s.Value[0])
}
func (s *statValue) DeepCopyMapValue() bpf.MapValue {
	v := &statValue{
		Value: make([]int64, runtime.NumCPU()),
	}
	copy(v.Value, s.Value)
	return v
}

func (k *Observer) startUpdateMapMetrics() {
	update := func() {
		for _, m := range sensors.AllMaps {
			pin := filepath.Join(k.mapDir, m.Name)
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
			sum := int64(0)
			for cpu := int(0); cpu < runtime.NumCPU(); cpu++ {
				sum += v.Value[cpu]
			}
			metrics.ExecveMapSize.WithLabelValues(m.Name, strconv.Itoa(int(mapLink.MapInfo.MaxEntries))).Set(float64(sum))
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
