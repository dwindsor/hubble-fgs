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
	"maps"
	"slices"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type namespaceKey struct {
	name string
}

type workloadKey struct {
	name string
	kind string
}

type processKey struct {
	name      string
	arguments string
}

type connectionKey struct {
	destinationName string
	destinationPort uint64
}

type connectionMap map[connectionKey]*appModelV1.ApplicationConnection
type processMap map[processKey]connectionMap
type workloadMap map[workloadKey]processMap
type namespaceMap map[namespaceKey]workloadMap

func handleNetworkEvent(nsMap namespaceMap, nk NetworkKey, bc byteCounter) {
	if nk.DestinationPort == 0 {
		// This is a summary that aggregates all the destination ports.
		// Ignore it for building application model.
		return
	}
	nsKey := namespaceKey{name: nk.SourceNamespace}
	wlkey := workloadKey{name: nk.SourceWorkloadName, kind: nk.SourceWorkloadKind}
	pskey := processKey{name: nk.SourceProcessName, arguments: nk.SourceProcessArgs}
	connKey := connectionKey{destinationName: nk.DestinationName, destinationPort: nk.DestinationPort}
	if _, ok := nsMap[nsKey]; !ok {
		nsMap[nsKey] = make(workloadMap)
	}
	if _, ok := nsMap[nsKey][wlkey]; !ok {
		nsMap[nsKey][wlkey] = make(processMap)
	}
	if _, ok := nsMap[nsKey][wlkey][pskey]; !ok {
		nsMap[nsKey][wlkey][pskey] = make(connectionMap)
	}
	nsMap[nsKey][wlkey][pskey][connKey] = &appModelV1.ApplicationConnection{
		DestinationName: connKey.destinationName,
		DestinationPort: connKey.destinationPort,
		BytesSent:       bc.BytesSent(),
		BytesReceived:   bc.BytesReceived(),
	}
}

func handleProcessEvent(nsMap namespaceMap, pk ProcessKey, _ ProcessValue) {
	nsKey := namespaceKey{name: pk.Namespace}
	wlkey := workloadKey{name: pk.WorkloadName, kind: pk.WorkloadKind}
	pskey := processKey{name: pk.Name, arguments: pk.Args}
	if _, ok := nsMap[nsKey]; !ok {
		nsMap[nsKey] = make(workloadMap)
	}
	if _, ok := nsMap[nsKey][wlkey]; !ok {
		nsMap[nsKey][wlkey] = make(processMap)
	}
	if _, ok := nsMap[nsKey][wlkey][pskey]; !ok {
		nsMap[nsKey][wlkey][pskey] = make(connectionMap)
	}
}

func sortNamespace(a, b *appModelV1.ApplicationNamespace) int {
	return strings.Compare(a.Name, b.Name)
}

func sortProcess(a, b *appModelV1.ApplicationProcess) int {
	return strings.Compare(a.Name+a.Arguments, b.Name+b.Arguments)
}

func sortWorkload(a, b *appModelV1.ApplicationWorkload) int {
	if kindComp := strings.Compare(a.Kind, b.Kind); kindComp != 0 {
		return kindComp
	}
	return strings.Compare(a.Name, b.Name)
}

func sortConnection(a, b *appModelV1.ApplicationConnection) int {
	if nameComp := strings.Compare(a.DestinationName, b.DestinationName); nameComp != 0 {
		return nameComp
	}
	if a.DestinationPort >= b.DestinationPort {
		return int(a.DestinationPort - b.DestinationPort)

	}
	return -1
}

func namespaceMapToApplicationModel(nsMap namespaceMap) *appModelV1.ApplicationModelEvent {
	result := &appModelV1.ApplicationModelEvent{}
	result.ApplicationModel = &appModelV1.ApplicationModel{}
	result.ApplicationModel.Host = &appModelV1.ApplicationHost{}
	result.NodeName = node.GetNodeNameForExport()
	result.ClusterName = option.Config.ClusterName
	result.Time = timestamppb.Now()
	for key, val := range nsMap {
		if key.name == HostNamespace {
			// There is no workload info for host processes.
			for _, wlval := range val {
				for pskey, psval := range wlval {
					ps := &appModelV1.ApplicationProcess{
						Name:        pskey.name,
						Arguments:   pskey.arguments,
						Connections: slices.Collect(maps.Values(psval)),
					}
					result.ApplicationModel.Host.Processes = append(result.ApplicationModel.Host.Processes, ps)
				}
			}
		} else {
			ns := &appModelV1.ApplicationNamespace{
				Name: key.name,
			}
			for wlkey, wlval := range val {
				wl := &appModelV1.ApplicationWorkload{
					Name: wlkey.name,
					Kind: wlkey.kind,
				}
				for pskey, psval := range wlval {
					ps := &appModelV1.ApplicationProcess{
						Name:        pskey.name,
						Arguments:   pskey.arguments,
						Connections: slices.Collect(maps.Values(psval)),
					}
					wl.Processes = append(wl.Processes, ps)
				}
				ns.Workloads = append(ns.Workloads, wl)
			}
			result.ApplicationModel.Namespaces = append(result.ApplicationModel.Namespaces, ns)
		}
	}
	// TODO(michi): Not very efficient. Optimize if anybody complains.
	slices.SortFunc(result.ApplicationModel.Namespaces, sortNamespace)
	for _, ns := range result.ApplicationModel.Namespaces {
		slices.SortFunc(ns.Workloads, sortWorkload)
		for _, wl := range ns.Workloads {
			slices.SortFunc(wl.Processes, sortProcess)
			for _, ps := range wl.Processes {
				slices.SortFunc(ps.Connections, sortConnection)
			}
		}
	}
	slices.SortFunc(result.ApplicationModel.Host.Processes, sortProcess)
	for _, ps := range result.ApplicationModel.Host.Processes {
		slices.SortFunc(ps.Connections, sortConnection)
	}
	return result
}

func ProcessModelToApplicationModel(res *tetragon.GetProcessModelResponse) *appModelV1.ApplicationModelEvent {
	// Ignore quota info for now.
	monitor, _, processes := ConvertToMonitorData(res, true)
	nsMap := make(namespaceMap)
	for key, val := range monitor {
		handleNetworkEvent(nsMap, key, val)
	}
	for key, val := range processes {
		handleProcessEvent(nsMap, key, val)
	}
	return namespaceMapToApplicationModel(nsMap)
}

func modelToMonitorData(nmd NetworkMonitorData, pmd ProcessMonitorData, app *appModelV1.ApplicationModel) {
	for _, ns := range app.GetNamespaces() {
		for _, wl := range ns.GetWorkloads() {
			for _, ps := range wl.GetProcesses() {
				if len(ps.GetConnections()) == 0 {
					pmk := ProcessKey{
						Namespace:    ns.GetName(),
						WorkloadKind: wl.GetKind(),
						WorkloadName: wl.GetName(),
						Name:         ps.GetName(),
						Args:         ps.GetArguments(),
					}
					pmd[pmk] = ProcessValue{}
					continue
				}
				for _, conn := range ps.GetConnections() {
					nmk := NetworkKey{
						SourceNamespace:    ns.GetName(),
						SourceWorkloadKind: wl.GetKind(),
						SourceWorkloadName: wl.GetName(),
						SourceProcessName:  ps.GetName(),
						SourceProcessArgs:  ps.GetArguments(),
						DestinationName:    conn.GetDestinationName(),
						DestinationPort:    conn.GetDestinationPort(),
					}
					if val, ok := nmd[nmk]; ok {
						val.TXBytes += conn.BytesSent
						val.RXBytes += conn.BytesSent
					} else {
						nmd[nmk] = NetworkMonitorValue{
							TXBytes: conn.GetBytesSent(),
							RXBytes: conn.GetBytesReceived(),
						}
					}
				}
			}
		}
	}
	for _, ps := range app.GetHost().GetProcesses() {
		if len(ps.GetConnections()) == 0 {
			pmk := ProcessKey{
				Namespace:    HostNamespace,
				WorkloadKind: HostKind,
				WorkloadName: HostWorkload,
				Name:         ps.GetName(),
				Args:         ps.GetArguments(),
			}
			pmd[pmk] = ProcessValue{}
			continue
		}
		for _, conn := range ps.GetConnections() {
			nmk := NetworkKey{
				SourceNamespace:    HostNamespace,
				SourceWorkloadKind: HostKind,
				SourceWorkloadName: HostWorkload,
				SourceProcessName:  ps.GetName(),
				SourceProcessArgs:  ps.GetArguments(),
				DestinationName:    conn.GetDestinationName(),
				DestinationPort:    conn.GetDestinationPort(),
			}
			if val, ok := nmd[nmk]; ok {
				val.TXBytes += conn.BytesSent
				val.RXBytes += conn.BytesSent
			} else {
				nmd[nmk] = NetworkMonitorValue{
					TXBytes: conn.GetBytesSent(),
					RXBytes: conn.GetBytesReceived(),
				}
			}
		}
	}
}

func Merge(m1, m2 *appModelV1.ApplicationModel) *appModelV1.ApplicationModel {
	nmd := NetworkMonitorData{}
	pmd := ProcessMonitorData{}
	modelToMonitorData(nmd, pmd, m1)
	modelToMonitorData(nmd, pmd, m2)
	nsMap := make(namespaceMap)
	for key, val := range nmd {
		handleNetworkEvent(nsMap, key, val)
	}
	for key, val := range pmd {
		handleProcessEvent(nsMap, key, val)
	}
	return namespaceMapToApplicationModel(nsMap).GetApplicationModel()
}
