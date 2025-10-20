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
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

const (
	HostNamespace        = "<host-namespace>"
	HostWorkload         = "<host-workload>"
	WorkloadDestinations = "<wl-destinations>"
	HostKind             = "<host-kind>"
)

type namespaceKey struct {
	name string
}

type workloadKey struct {
	name string
	kind v1alpha.WorkloadKind
}

type processKey struct {
	name      string
	arguments string
}

type connectionKey struct {
	destination *appModelV1.Destination
}

type processValue struct {
	connections     connectionMap
	inInitTree      bool
	syscalls        *appModelV1.ApplicationSyscalls
	firstStartTime  *time.Time
	latestStartTime *time.Time
	latestExitTime  *time.Time
}

type connectionMap map[connectionKey]*appModelV1.ApplicationConnection
type processMap map[processKey]processValue
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
	connKey := connectionKey{destination: nwKeyToDestination(&nk)}
	if _, ok := nsMap[nsKey]; !ok {
		nsMap[nsKey] = make(workloadMap)
	}
	if _, ok := nsMap[nsKey][wlkey]; !ok {
		nsMap[nsKey][wlkey] = make(processMap)
	}
	if _, ok := nsMap[nsKey][wlkey][pskey]; !ok {
		nsMap[nsKey][wlkey][pskey] = processValue{
			connections: make(connectionMap),
		}
	}
	nsMap[nsKey][wlkey][pskey].connections[connKey] = &appModelV1.ApplicationConnection{
		Destination: nwKeyToDestination(&nk),
		Stats: &appModelV1.ConnectionStats{
			TxBytes:           bc.GetTxBytes(),
			RxBytes:           bc.GetRxBytes(),
			DefaultAllowBytes: bc.GetAllowDefaultBytes(),
			DefaultDropBytes:  bc.GetDenyDefaultBytes(),
			TxDrops:           bc.GetTxDrops(),
			TxQuota:           bc.GetTxQuota(),
			TxQuotaUsage:      bc.GetTxUsage(),
			LastQuotaReset:    maybeTimeToTimestamp(bc.GetLastReset()),
			NextQuotaReset:    maybeTimeToTimestamp(bc.GetNextReset()),
		},
		Policy: &appModelV1.NetworkPolicy{
			PolicyName: bc.GetPolicy(),
			RuleName:   bc.GetRule(),
		},
	}
}

func maybeTimeToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func handleProcessEvent(nsMap namespaceMap, pk ProcessKey, psval ProcessValue) {
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
		nsMap[nsKey][wlkey][pskey] = processValue{
			connections:     make(connectionMap),
			inInitTree:      psval.InInitTree,
			syscalls:        psval.Syscalls,
			firstStartTime:  psval.FirstStartTime,
			latestStartTime: psval.LatestStartTime,
			latestExitTime:  psval.LatestExitTime,
		}
	}
}

// translateWorkloadKind translates the process model workload kind into an app
// model workload kind enum.
func translateWorkloadKind(kind string) v1alpha.WorkloadKind {
	key := fmt.Sprintf("WORKLOAD_KIND_%s", strings.ToUpper(kind))
	val, ok := v1alpha.WorkloadKind_value[key]
	if ok {
		return v1alpha.WorkloadKind(val)
	}
	// <host-kind> will fall through to here
	return v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED
}

func namespaceMapToApplicationModel(nsMap namespaceMap, nsFilter map[string]bool) *appModelV1.ApplicationModelEvent {
	result := &appModelV1.ApplicationModelEvent{}
	result.ApplicationModel = &appModelV1.ApplicationModel{}
	if id, err := uuid.NewV7(); err == nil {
		result.ApplicationModel.Id = id.String()
	}
	result.ApplicationModel.Host = &appModelV1.ApplicationHost{}
	result.NodeName = node.GetNodeNameForExport()
	result.ClusterName = option.Config.ClusterName
	result.Time = timestamppb.Now()
	for key, val := range nsMap {
		_, ok := nsFilter[key.name]
		if ok {
			continue
		}
		if key.name == HostNamespace {
			// There is no workload info for host processes.
			for _, wlval := range val {
				for pskey, psval := range wlval {
					ps := &appModelV1.ApplicationProcessGroup{
						Name:            pskey.name,
						Arguments:       pskey.arguments,
						Connections:     slices.Collect(maps.Values(psval.connections)),
						InInitTree:      wrapperspb.Bool(psval.inInitTree),
						SyscallInfo:     psval.syscalls,
						FirstStartTime:  maybeTimeToTimestamp(psval.firstStartTime),
						LatestStartTime: maybeTimeToTimestamp(psval.latestStartTime),
						LatestExitTime:  maybeTimeToTimestamp(psval.latestExitTime),
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
					ps := &appModelV1.ApplicationProcessGroup{
						Name:            pskey.name,
						Arguments:       pskey.arguments,
						Connections:     slices.Collect(maps.Values(psval.connections)),
						InInitTree:      wrapperspb.Bool(psval.inInitTree),
						SyscallInfo:     psval.syscalls,
						FirstStartTime:  maybeTimeToTimestamp(psval.firstStartTime),
						LatestStartTime: maybeTimeToTimestamp(psval.latestStartTime),
						LatestExitTime:  maybeTimeToTimestamp(psval.latestExitTime),
					}
					wl.Processes = append(wl.Processes, ps)
				}
				ns.Workloads = append(ns.Workloads, wl)
			}
			result.ApplicationModel.Namespaces = append(result.ApplicationModel.Namespaces, ns)
		}
	}
	// TODO(michi): Not very efficient. Optimize if anybody complains.
	EnsureSorted(result.ApplicationModel)
	return result
}

func ProcessModelToApplicationModel(processModel []*types.ProcessModel, nsFilter map[string]bool) *appModelV1.ApplicationModelEvent {
	// Ignore quota info for now.
	monitor, _, processes := ConvertToMonitorData(processModel, true)
	nsMap := make(namespaceMap)
	for key, val := range monitor {
		handleNetworkEvent(nsMap, key, val)
	}
	for key, val := range processes {
		handleProcessEvent(nsMap, key, val)
	}
	return namespaceMapToApplicationModel(nsMap, nsFilter)
}

func DestinationNameAppModel(dst *appModelV1.Destination) string {
	var name string

	// Preamble
	switch dt := dst.Type.(type) {
	case *appModelV1.Destination_Dns:
		name = strings.Join(dt.Dns.DestinationNames, ",")
	case *appModelV1.Destination_Ip:
		name = dt.Ip.Ip
	case *appModelV1.Destination_Workload:
		name = fmt.Sprintf("%s/%s:%s", dt.Workload.Namespace, prettyWorkloadKind(dt.Workload.Kind), dt.Workload.Name)
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", dt))
	}

	// Port
	if dst.Port != 0 {
		name = fmt.Sprintf("%s:%d", name, dst.Port)
	}

	return name
}

func ToMonitorData(nmd NetworkMonitorData, pmd ProcessMonitorData, app *appModelV1.ApplicationModel) {
	for _, ns := range app.GetNamespaces() {
		for _, wl := range ns.GetWorkloads() {
			for _, ps := range wl.GetProcesses() {
				pmk := ProcessKey{
					Namespace:    ns.GetName(),
					WorkloadKind: wl.GetKind(),
					WorkloadName: wl.GetName(),
					Name:         ps.GetName(),
					Args:         ps.GetArguments(),
				}
				pmd[pmk] = ProcessValue{}
				for _, conn := range ps.GetConnections() {
					nmk := NetworkKey{
						SourceNamespace:    ns.GetName(),
						SourceWorkloadKind: wl.GetKind(),
						SourceWorkloadName: wl.GetName(),
						SourceProcessName:  ps.GetName(),
						SourceProcessArgs:  ps.GetArguments(),
					}
					addDestinationInfoAppModel(conn.Destination, &nmk)
					nmd[nmk] = NetworkMonitorValue{
						TXBytes: conn.Stats.TxBytes,
						RXBytes: conn.Stats.RxBytes,
					}
				}
			}
		}
	}
	for _, ps := range app.GetHost().GetProcesses() {
		pmk := ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			WorkloadName: HostWorkload,
			Name:         ps.GetName(),
			Args:         ps.GetArguments(),
		}
		pmd[pmk] = ProcessValue{}
		for _, conn := range ps.GetConnections() {
			nmk := NetworkKey{
				SourceNamespace:    HostNamespace,
				SourceWorkloadKind: v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
				SourceWorkloadName: HostWorkload,
				SourceProcessName:  ps.GetName(),
				SourceProcessArgs:  ps.GetArguments(),
			}
			addDestinationInfoAppModel(conn.Destination, &nmk)
			nmd[nmk] = NetworkMonitorValue{
				TXBytes: conn.Stats.TxBytes,
				RXBytes: conn.Stats.RxBytes,
			}
		}
	}
}

func Merge(m1, m2 *appModelV1.ApplicationModel) *appModelV1.ApplicationModel {
	nmd := NetworkMonitorData{}
	pmd := ProcessMonitorData{}
	ToMonitorData(nmd, pmd, m1)
	ToMonitorData(nmd, pmd, m2)
	nsMap := make(namespaceMap)
	for key, val := range nmd {
		handleNetworkEvent(nsMap, key, val)
	}
	for key, val := range pmd {
		handleProcessEvent(nsMap, key, val)
	}
	emptyFilter := make(map[string]bool)
	return namespaceMapToApplicationModel(nsMap, emptyFilter).GetApplicationModel()
}
