// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/go-cmp/cmp"
)

type NetworkKey struct {
	SourceNamespace    string
	SourceWorkloadKind string
	SourceWorkloadName string
	SourceProcessName  string
	DestinationName    string
	DestinationPort    uint64
}

func (nk NetworkKey) String() string {
	var source, destination string
	if nk.SourceNamespace == HostNamespace {
		source = "host"
	} else {
		source = fmt.Sprintf("%s/%s:%s", nk.SourceNamespace, nk.SourceWorkloadKind, nk.SourceWorkloadName)
	}
	if nk.DestinationPort == 0 {
		destination = nk.DestinationName
	} else {
		destination = fmt.Sprintf("%s:%d", nk.DestinationName, nk.DestinationPort)
	}
	return fmt.Sprintf("%s > %s", source, destination)
}

type NetworkMonitorValue struct {
	TXBytes uint64
	RXBytes uint64
}

func getByteSize(b uint64) string {
	for _, unit := range []string{"", "K", "M", "G", "T", "P"} {
		if b < 1024 {
			return fmt.Sprintf("%d%sB", b, unit)
		}
		b >>= 10
	}
	return fmt.Sprintf("%dEB", b)
}

func (nmv NetworkMonitorValue) String() string {
	return fmt.Sprintf("%s sent %s received", getByteSize(nmv.TXBytes), getByteSize(nmv.RXBytes))
}

type NetworkQuotaValue struct {
	TXBytes uint64
	RXBytes uint64
	TXDrops uint64
	TXQuota uint64
	TXUsage uint64
	Reset   time.Time
}

type byteCounter interface {
	BytesSent() uint64
	BytesReceived() uint64
}

func (nmv NetworkMonitorValue) BytesSent() uint64 {
	return nmv.TXBytes
}

func (nmv NetworkMonitorValue) BytesReceived() uint64 {
	return nmv.RXBytes
}

func (nqv NetworkQuotaValue) BytesSent() uint64 {
	return nqv.TXBytes
}

func (nqv NetworkQuotaValue) BytesReceived() uint64 {
	return nqv.RXBytes
}

func (nqv NetworkQuotaValue) String() string {
	now := time.Now()
	var reset string
	if now.Before(nqv.Reset) {
		reset = fmt.Sprintf("reset in %s", nqv.Reset.Sub(now).Truncate(time.Second))
	} else {
		reset = "reset on next send"
	}
	return fmt.Sprintf("quota %s of %s (%.2f%%) used %s dropped %s",
		getByteSize(nqv.TXUsage), getByteSize(nqv.TXQuota),
		100*float64(nqv.TXUsage)/float64(nqv.TXQuota),
		getByteSize(nqv.TXDrops), reset,
	)
}

type NetworkMonitorData map[NetworkKey]NetworkMonitorValue
type NetworkQuotaData map[NetworkKey]NetworkQuotaValue
type ProcessMonitorData map[ProcessKey]ProcessValue

type ProcessKey struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	Name         string
}

type ProcessValue struct{}

func sortNetworkKeys(a, b NetworkKey) int {
	if result := strings.Compare(a.SourceNamespace, b.SourceNamespace); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadKind, b.SourceWorkloadKind); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadName, b.SourceWorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceProcessName, b.SourceProcessName); result != 0 {
		return result
	}
	ipA, errA := netip.ParseAddr(a.DestinationName)
	ipB, errB := netip.ParseAddr(b.DestinationName)
	if errA == nil && errB == nil {
		if result := ipA.Compare(ipB); result != 0 {
			return result
		}
	} else if errA != nil && errB == nil {
		return -1
	} else if errA == nil {
		return 1
	} else {
		if result := strings.Compare(a.DestinationName, b.DestinationName); result != 0 {
			return result
		}
	}
	if a.DestinationPort >= b.DestinationPort {
		return int(a.DestinationPort - b.DestinationPort)
	}
	return -1
}

func (nmd NetworkMonitorData) Print() {
	keys := slices.Collect(maps.Keys(nmd))
	slices.SortFunc(keys, sortNetworkKeys)
	for _, key := range keys {
		fmt.Println(key, nmd[key])
	}
}

func (nqd NetworkQuotaData) Print() {
	for key, val := range nqd {
		fmt.Println(key, val)
	}
}

func getDestinationName(dst *tetragon.Destination) string {
	dstName := "unknown"
	if len(dst.GetDestinationNames()) > 0 {
		dstName = strings.TrimSuffix(dst.GetDestinationNames()[0], ".")
	} else if dst.GetDestinationPod() != nil {
		dstName = fmt.Sprintf("%s/%s:%s",
			dst.GetDestinationPod().GetNamespace(),
			dst.GetDestinationPod().GetWorkloadKind(),
			dst.GetDestinationPod().GetWorkload())
	} else if dst.GetDestinationService() != nil {
		dstName = fmt.Sprintf("%s/Service:%s",
			dst.GetDestinationService().GetNamespace(),
			dst.GetDestinationService().GetName())
	}
	return dstName
}

func getNetworkMonitorKey(process *tetragon.ProcessModel, dst *tetragon.Destination, includeProcess bool) NetworkKey {
	dstName := getDestinationName(dst)
	nwKey := NetworkKey{
		SourceNamespace:    process.GetNamespace(),
		SourceWorkloadName: process.GetWorkload().GetName(),
		SourceWorkloadKind: process.GetWorkload().GetKind(),
		DestinationName:    dstName,
		DestinationPort:    dst.GetPort(),
	}
	if includeProcess {
		nwKey.SourceProcessName = process.GetBinary()
	}
	return nwKey
}

func getProcessMonitorKey(process *tetragon.ProcessModel) ProcessKey {
	return ProcessKey{
		Namespace:    process.GetNamespace(),
		WorkloadName: process.GetWorkload().GetName(),
		WorkloadKind: process.GetWorkload().GetKind(),
		Name:         process.GetBinary(),
	}
}

func getNetworkQuotaValue(dst *tetragon.Destination) NetworkQuotaValue {
	return NetworkQuotaValue{
		TXBytes: dst.GetStats().GetTxBytes(),
		RXBytes: dst.GetStats().GetRxBytes(),
		TXDrops: dst.GetStats().GetTxDrops(),
		TXQuota: dst.GetStats().GetTxLimit(),
		TXUsage: dst.GetStats().GetTxQuota(),
		Reset:   dst.GetStats().GetKtimeTxReset().AsTime(),
	}
}

func ConvertToMonitorData(res *tetragon.GetProcessModelResponse, includeProcess bool) (NetworkMonitorData, NetworkQuotaData, ProcessMonitorData) {
	result := NetworkMonitorData{}
	quota := NetworkQuotaData{}
	proc := ProcessMonitorData{}
	for _, process := range res.GetProcesses() {
		if len(process.GetDest()) == 0 {
			processKey := getProcessMonitorKey(process)
			proc[processKey] = ProcessValue{}
			continue
		}
		for _, dst := range process.GetDest() {
			if dst.GetStats() == nil {
				continue
			}
			key := getNetworkMonitorKey(process, dst, includeProcess)
			if dst.GetPort() != 0 {
				if _, ok := result[key]; !ok {
					result[key] = NetworkMonitorValue{}
				}
				currentValue := result[key]
				currentValue.TXBytes += dst.GetStats().GetTxBytes()
				currentValue.RXBytes += dst.GetStats().GetRxBytes()
				result[key] = currentValue
			} else if process.GetBinary() == "" && dst.GetStats().GetTxLimit() > 0 {
				// This is quota-related stats.
				quota[key] = getNetworkQuotaValue(dst)
			}
		}
	}
	return result, quota, proc
}

func Diff(current, new NetworkMonitorData) NetworkMonitorData {
	diff := NetworkMonitorData{}
	for newKey, newValue := range new {
		if currentValue, ok := current[newKey]; ok {
			if !cmp.Equal(currentValue, newValue) {
				diff[newKey] = NetworkMonitorValue{
					TXBytes: newValue.TXBytes - currentValue.TXBytes,
					RXBytes: newValue.RXBytes - currentValue.RXBytes,
				}
			}
		} else {
			diff[newKey] = NetworkMonitorValue{
				TXBytes: newValue.TXBytes,
				RXBytes: newValue.RXBytes,
			}
		}
	}
	return diff
}
