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
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/prometheus/client_golang/prometheus"
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
		for i := 0; i < fileapi.FileExecMetricMax; i++ {
			sum.M[i] += val.M[i]
		}
	}
	return nil
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	sum := fileapi.FileExecStats{}
	err := filepath.Walk(option.Config.MapDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), "file_exec_stats_map") {
			return collectMapStats(path, &sum)
		}
		return nil
	})
	if err != nil {
		fileExecCollectorErrors.Inc()
		return
	}

	for i := 0; i < fileapi.FileExecMetricMax; i++ {
		ch <- fileExecEbpfErrors.MustMetric(float64(sum.M[i]), fileapi.FileExecMetricTable[i])
	}
}
