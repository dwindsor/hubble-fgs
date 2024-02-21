//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package filemetrics

import (
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	"github.com/prometheus/client_golang/prometheus"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfInodeMapCollector struct{}

func NewBPFInodeMapCollector() prometheus.Collector {
	return &bpfInodeMapCollector{}
}

func (c *bpfInodeMapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- fileMapInodeFile.Desc()
	ch <- fileMapInodeDir.Desc()
}

func countInodeMapEnties(handle *ebpf.Map) uint64 {
	var key fileapi.HashMapFileKey
	var val fileapi.HashMapFileVal
	var count uint64

	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		count++
	}
	return count
}

func (c *bpfInodeMapCollector) Collect(ch chan<- prometheus.Metric) {
	for _, tp := range pol.FileMonitoringTable.GetValuesFIM() {
		filePinPath := path.Join(option.Config.BpfDir, sensors.PathJoin(tp.PinPath, "hash_map_file_alloc"))
		fileMapHandle, err := ebpf.LoadPinnedMap(filePinPath, nil)
		if err != nil {
			return
		}
		defer fileMapHandle.Close()

		ch <- fileMapInodeFile.MustMetric(float64(countInodeMapEnties(fileMapHandle)), tp.PolicyName)

		dirPinPath := path.Join(option.Config.BpfDir, sensors.PathJoin(tp.PinPath, "hash_map_dir_alloc"))
		dirMapHandle, err := ebpf.LoadPinnedMap(dirPinPath, nil)
		if err != nil {
			return
		}
		defer dirMapHandle.Close()

		ch <- fileMapInodeDir.MustMetric(float64(countInodeMapEnties(dirMapHandle)), tp.PolicyName)
	}
}
