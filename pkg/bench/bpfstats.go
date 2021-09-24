//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bench

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

func EnableBpfStats() {
	err := os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte("1"), 0666)
	if err != nil {
		log.Fatalf("failed to enable bpf stats: %v", err)
	}
}

type BpfProgStats struct {
	Id     int64  `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	RunNs  int64  `json:"run_time_ns"`
	RunCnt int64  `json:"run_cnt"`
	// ...
}

func (bps *BpfProgStats) String() string {
	duration := time.Duration(0)
	if bps.RunCnt > 0 {
		duration = time.Duration(bps.RunNs / bps.RunCnt)
	}
	name := bps.Name
	if len(name) == 0 {
		name = "<unnamed>"
	}

	return fmt.Sprintf("%-16s [%s/%d]:\t%.2fµs (%d)",
		name, bps.Type, bps.Id,
		float64(duration)/float64(time.Microsecond), bps.RunCnt)
}

func GetBpfStatsSince(oldStats map[int64]*BpfProgStats) map[int64]*BpfProgStats {
	newStats := GetBpfStats()
	for id, newStat := range newStats {
		if oldStat, ok := oldStats[id]; ok {
			newStat.RunNs -= oldStat.RunNs
			newStat.RunCnt -= oldStat.RunCnt
		}
	}
	return newStats
}

func GetBpfStats() map[int64]*BpfProgStats {
	out, err := exec.Command("/bin/sh", "-c", "bpftool prog show -j").Output()
	if err != nil {
		log.Printf("Failed to query bpf stats: %s\n", err)
		return nil
	}

	var stats []BpfProgStats
	err = json.Unmarshal(out, &stats)
	if err != nil {
		log.Printf("Failed to parse bpf stats: %s\n", err)
		return nil
	}

	m := make(map[int64]*BpfProgStats)
	for id := range stats {
		var s = &stats[id]
		m[s.Id] = s
	}
	return m
}
