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
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/go-cmp/cmp"
)

type NetworkKey struct {
	SourceNamespace    string
	SourceWorkloadKind string
	SourceWorkloadName string
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

func (nmd NetworkMonitorData) Print() {
	for key, val := range nmd {
		fmt.Println(key, val)
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
	}
	return dstName
}

func getNetworkMonitorKey(process *tetragon.ProcessModel, dst *tetragon.Destination) NetworkKey {
	dstName := getDestinationName(dst)
	return NetworkKey{
		SourceNamespace:    process.GetNamespace(),
		SourceWorkloadName: process.GetWorkload().GetName(),
		SourceWorkloadKind: process.GetWorkload().GetKind(),
		DestinationName:    dstName,
		DestinationPort:    dst.GetPort(),
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

func ConvertToNetworkData(res *tetragon.GetProcessModelResponse) (NetworkMonitorData, NetworkQuotaData) {
	result := NetworkMonitorData{}
	quota := NetworkQuotaData{}
	for _, process := range res.GetProcesses() {
		for _, dst := range process.GetDest() {
			if dst.GetStats() == nil {
				continue
			}
			key := getNetworkMonitorKey(process, dst)
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
	return result, quota
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
