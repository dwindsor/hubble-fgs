// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package filemetrics

import (
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- fileExecEbpfErrors.Desc()
}

func collectMapStats(mapPath string, sum *fileapi.FileExecStats) error {
	mapHandle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return err
	}
	defer mapHandle.Close()

	var zero uint32
	var allCpuValue []fileapi.FileExecStats
	if err := mapHandle.Lookup(zero, &allCpuValue); err != nil {
		return err
	}

	for _, val := range allCpuValue {
		for i := range fileapi.FileExecMetricMax {
			sum.M[i] += val.M[i]
		}
	}
	return nil
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	sum := fileapi.FileExecStats{}
	for _, tp := range pol.FileExecMonitoringTable.GetValuesFileExec() {
		path := filepath.Join(option.Config.BpfDir, tp.PolicyName, "file_exec_stats_map")
		if err := collectMapStats(path, &sum); err != nil {
			fileExecCollectorErrors.Inc()
			return
		}
	}

	for i := range fileapi.FileExecMetricMax {
		ch <- fileExecEbpfErrors.MustMetric(float64(sum.M[i]), fileapi.FileExecMetricTable[i])
	}
}
