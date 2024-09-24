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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
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
	ch <- fileMapInode.Desc()
}

func countInodeMapEnties(handle *ebpf.Map) uint64 {
	var key fileapi.InodeKey
	var val fileapi.InodeVal
	var count uint64

	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		count++
	}
	return count
}

func (c *bpfInodeMapCollector) Collect(ch chan<- prometheus.Metric) {
	for _, tp := range pol.FileMonitoringTable.GetValuesFIM() {
		inodePinPath := filepath.Join(option.Config.BpfDir, tp.PolicyName, "hash_map_inode_alloc")
		inodeMapHandle, err := ebpf.LoadPinnedMap(inodePinPath, nil)
		if err != nil {
			FileTotalErrorsInc(MetricsInodeMap)
			return
		}
		defer inodeMapHandle.Close()

		ch <- fileMapInode.MustMetric(float64(countInodeMapEnties(inodeMapHandle)), tp.PolicyName)
	}
}
