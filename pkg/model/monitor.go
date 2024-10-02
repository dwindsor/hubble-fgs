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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/go-cmp/cmp"
)

type NetworkMonitorKey struct {
	SourceNamespace    string
	SourceWorkloadKind string
	SourceWorkloadName string
	DestinationName    string
	DestinationPort    uint64
}

func (nmk NetworkMonitorKey) String() string {
	var source string
	if nmk.SourceNamespace == HostNamespace {
		source = "host"
	} else {
		source = fmt.Sprintf("%s/%s:%s", nmk.SourceNamespace, nmk.SourceWorkloadKind, nmk.SourceWorkloadName)
	}
	destination := fmt.Sprintf("%s:%d", nmk.DestinationName, nmk.DestinationPort)
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

type NetworkMonitorData map[NetworkMonitorKey]NetworkMonitorValue

func (nmd NetworkMonitorData) Print() {
	for key, val := range nmd {
		fmt.Println(key, val)
	}
}

func ConvertToNetworkMonitorData(res *tetragon.GetProcessModelResponse) NetworkMonitorData {
	result := NetworkMonitorData{}
	for _, process := range res.GetProcesses() {
		for _, dst := range process.GetDest() {
			if dst.GetPort() != 0 {
				dstName := "unknown"
				if len(dst.GetDestinationNames()) > 0 {
					dstName = strings.TrimSuffix(dst.GetDestinationNames()[0], ".")
				} else if dst.GetDestinationPod() != nil {
					dstName = fmt.Sprintf("%s/%s:%s",
						dst.GetDestinationPod().GetNamespace(),
						dst.GetDestinationPod().GetWorkloadKind(),
						dst.GetDestinationPod().GetWorkload())
				}
				key := NetworkMonitorKey{
					SourceNamespace:    process.GetNamespace(),
					SourceWorkloadName: process.GetWorkload().GetName(),
					SourceWorkloadKind: process.GetWorkload().GetKind(),
					DestinationName:    dstName,
					DestinationPort:    dst.GetPort(),
				}
				if _, ok := result[key]; !ok {
					result[key] = NetworkMonitorValue{}
				}
				currentValue := result[key]
				currentValue.TXBytes += dst.GetStats().GetTxBytes()
				currentValue.RXBytes += dst.GetStats().GetRxBytes()
				result[key] = currentValue
			}
		}
	}
	return result
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
