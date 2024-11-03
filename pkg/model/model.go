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
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ApplicationModelEvent struct {
	ClusterName      string                 `json:"cluster_name,omitempty"`
	NodeName         string                 `json:"node_name,omitempty"`
	Time             *timestamppb.Timestamp `json:"time,omitempty"`
	ApplicationModel ApplicationModel       `json:"application_model,omitempty"`
}

type ApplicationModel struct {
	Namespaces []ApplicationNamespace `json:"namespaces,omitempty"`
	Host       ApplicationHost        `json:"host,omitempty"`
}

type ApplicationHost struct {
	Processes []ApplicationProcess `json:"processes,omitempty"`
}

type ApplicationNamespace struct {
	Name      string                `json:"name,omitempty"`
	Workloads []ApplicationWorkload `json:"workloads,omitempty"`
}

type ApplicationWorkload struct {
	Name      string               `json:"name,omitempty"`
	Kind      string               `json:"kind,omitempty"`
	Processes []ApplicationProcess `json:"processes,omitempty"`
}

type ApplicationProcess struct {
	Name        string                  `json:"name,omitempty"`
	Connections []ApplicationConnection `json:"connections,omitempty"`
}

type ApplicationConnection struct {
	DestinationName string `json:"destination_name,omitempty"`
	DestinationPort uint64 `json:"destination_port,omitempty"`
	BytesSent       uint64 `json:"bytes_sent,omitempty"`
	BytesReceived   uint64 `json:"bytes_received,omitempty"`
}

type namespaceKey struct {
	name string
}

type workloadKey struct {
	name string
	kind string
}

type processKey struct {
	name string
}

type connectionKey struct {
	destinationName string
	destinationPort uint64
}

type connectionMap map[connectionKey]ApplicationConnection
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
	pskey := processKey{name: nk.SourceProcessName}
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
	nsMap[nsKey][wlkey][pskey][connKey] = ApplicationConnection{
		DestinationName: connKey.destinationName,
		DestinationPort: connKey.destinationPort,
		BytesSent:       bc.BytesSent(),
		BytesReceived:   bc.BytesReceived(),
	}
}

func handleProcessEvent(nsMap namespaceMap, pk ProcessKey, _ ProcessValue) {
	nsKey := namespaceKey{name: pk.Namespace}
	wlkey := workloadKey{name: pk.WorkloadName, kind: pk.WorkloadKind}
	pskey := processKey{name: pk.Name}
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

func sortNamespace(a, b ApplicationNamespace) int {
	return strings.Compare(a.Name, b.Name)
}

func sortProcess(a, b ApplicationProcess) int {
	return strings.Compare(a.Name, b.Name)
}

func sortWorkload(a, b ApplicationWorkload) int {
	if kindComp := strings.Compare(a.Kind, b.Kind); kindComp != 0 {
		return kindComp
	}
	return strings.Compare(a.Name, b.Name)
}

func sortConnection(a, b ApplicationConnection) int {
	if nameComp := strings.Compare(a.DestinationName, b.DestinationName); nameComp != 0 {
		return nameComp
	}
	if a.DestinationPort >= b.DestinationPort {
		return int(a.DestinationPort - b.DestinationPort)

	}
	return -1
}

func namespaceMapToApplicationModel(nsMap namespaceMap) ApplicationModelEvent {
	result := ApplicationModelEvent{}
	result.ApplicationModel = ApplicationModel{}
	result.NodeName = node.GetNodeNameForExport()
	result.ClusterName = option.Config.ClusterName
	result.Time = timestamppb.Now()
	for key, val := range nsMap {
		if key.name == HostNamespace {
			// There is no workload info for host processes.
			for _, wlval := range val {
				for pskey, psval := range wlval {
					ps := ApplicationProcess{
						Name:        pskey.name,
						Connections: slices.Collect(maps.Values(psval)),
					}
					result.ApplicationModel.Host.Processes = append(result.ApplicationModel.Host.Processes, ps)
				}
			}
		} else {
			ns := ApplicationNamespace{
				Name: key.name,
			}
			for wlkey, wlval := range val {
				wl := ApplicationWorkload{
					Name: wlkey.name,
					Kind: wlkey.kind,
				}
				for pskey, psval := range wlval {
					ps := ApplicationProcess{
						Name:        pskey.name,
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

func ProcessModelToApplicationModel(res *tetragon.GetProcessModelResponse) ApplicationModelEvent {
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
