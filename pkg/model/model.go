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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"
	"uuid"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
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
	uid  string
}

type containerKey struct {
	cont types.ContainerInfo
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
	parents         []string // All unique immediate parent names for this binary/args tuple
	execIDs         []string
	firstStartTime  *time.Time
	latestStartTime *time.Time
	latestExitTime  *time.Time
	execCount       uint64
	exitCount       uint64
}

type connectionMap map[connectionKey]*appModelV1.ApplicationConnection
type processMap map[processKey]processValue
type containerMap map[containerKey]processMap
type workloadMap map[workloadKey]containerMap
type namespaceMap map[namespaceKey]workloadMap

func handleNetworkEvent(nsMap namespaceMap, nk NetworkKey, bc byteCounter) {
	if nk.DestinationPort == 0 {
		// This is a summary that aggregates all the destination ports.
		// Ignore it for building application model.
		return
	}
	nsKey := namespaceKey{name: nk.SourceNamespace}
	wlkey := workloadKey{
		name: nk.SourceWorkloadName,
		kind: nk.SourceWorkloadKind,
		uid:  nk.SourceWorkloadUID,
	}
	contKey := containerKey{cont: nk.SourceContainer}
	pskey := processKey{name: nk.SourceProcessName, arguments: nk.SourceProcessArgs}
	connKey := connectionKey{destination: nwKeyToDestination(&nk)}
	if _, ok := nsMap[nsKey]; !ok {
		nsMap[nsKey] = make(workloadMap)
	}
	if _, ok := nsMap[nsKey][wlkey]; !ok {
		nsMap[nsKey][wlkey] = make(containerMap)
	}
	if _, ok := nsMap[nsKey][wlkey][contKey]; !ok {
		nsMap[nsKey][wlkey][contKey] = make(processMap)
	}
	if _, ok := nsMap[nsKey][wlkey][contKey][pskey]; !ok {
		nsMap[nsKey][wlkey][contKey][pskey] = processValue{
			connections: make(connectionMap),
		}
	}
	nsMap[nsKey][wlkey][contKey][pskey].connections[connKey] = &appModelV1.ApplicationConnection{
		Destination: nwKeyToDestination(&nk),
		Stats: &appModelV1.ConnectionStats{
			TxBytes:               bc.GetTxBytes(),
			RxBytes:               bc.GetRxBytes(),
			DefaultAllowBytes:     bc.GetTxDefaultAllowBytes(),
			DefaultDropBytes:      bc.GetTxDefaultDropBytes(),
			TxDrops:               bc.GetTxDropBytes(), //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
			TxDropBytes:           bc.GetTxDropBytes(),
			TxDropPackets:         bc.GetTxDropPackets(),
			DefaultDropPackets:    bc.GetTxDefaultDropPackets(),
			DefaultAllowPackets:   bc.GetTxDefaultAllowPackets(),
			RxDropBytes:           bc.GetRxDropBytes(),
			RxDropPackets:         bc.GetRxDropPackets(),
			RxDefaultDropBytes:    bc.GetRxDefaultDropBytes(),
			RxDefaultDropPackets:  bc.GetRxDefaultDropPackets(),
			RxDefaultAllowBytes:   bc.GetRxDefaultAllowBytes(),
			RxDefaultAllowPackets: bc.GetRxDefaultAllowPackets(),
			Sessions:              bc.GetSessions(),
		},
		Policy: &appModelV1.NetworkPolicy{
			PolicyName: bc.GetPolicy(),
			RuleName:   bc.GetRule(),
		},
		Protocol:         nk.Protocol,
		ObservationPoint: nk.ObservationPoint,
	}
}

// MaybeTimeToTimestamp converts a *time.Time to a *timestamppb.Timestamp.
// Returns nil if the input is nil.
func MaybeTimeToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// processGroupHash generates a hash to identify a process group.
// The hash is a SHA256 of the process name and arguments.
func processGroupHash(name, arguments string) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte(arguments))
	return hex.EncodeToString(h.Sum(nil))
}

func handleProcessEvent(nsMap namespaceMap, pk ProcessKey, psval ProcessValue) {
	nsKey := namespaceKey{name: pk.Namespace}
	wlkey := workloadKey{
		name: pk.WorkloadName,
		kind: pk.WorkloadKind,
		uid:  pk.WorkloadUID,
	}
	contKey := containerKey{cont: pk.Container}
	pskey := processKey{name: pk.Name, arguments: pk.Args}
	if _, ok := nsMap[nsKey]; !ok {
		nsMap[nsKey] = make(workloadMap)
	}
	if _, ok := nsMap[nsKey][wlkey]; !ok {
		nsMap[nsKey][wlkey] = make(containerMap)
	}
	if _, ok := nsMap[nsKey][wlkey][contKey]; !ok {
		nsMap[nsKey][wlkey][contKey] = make(processMap)
	}
	// Get existing entry or create new one
	existing, exists := nsMap[nsKey][wlkey][contKey][pskey]
	if !exists {
		// Create new entry with process data
		nsMap[nsKey][wlkey][contKey][pskey] = processValue{
			connections:     make(connectionMap),
			inInitTree:      psval.InInitTree,
			syscalls:        psval.Syscalls,
			parents:         psval.Parents,
			execIDs:         psval.ExecIDs,
			firstStartTime:  psval.FirstStartTime,
			latestStartTime: psval.LatestStartTime,
			latestExitTime:  psval.LatestExitTime,
			execCount:       psval.ExecCount,
			exitCount:       psval.ExitCount,
		}
	} else {
		// Merge process data into existing entry (preserving connections)
		existing.inInitTree = psval.InInitTree
		existing.syscalls = psval.Syscalls
		existing.parents = psval.Parents
		existing.execIDs = psval.ExecIDs
		existing.firstStartTime = psval.FirstStartTime
		existing.latestStartTime = psval.LatestStartTime
		existing.latestExitTime = psval.LatestExitTime
		existing.execCount = psval.ExecCount
		existing.exitCount = psval.ExitCount
		nsMap[nsKey][wlkey][contKey][pskey] = existing
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
	result.ApplicationModel.Id = uuid.NewV7().String()
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
				for _, contval := range wlval {
					for pskey, psval := range contval {
						ps := &appModelV1.ApplicationProcessGroup{
							Hash:            processGroupHash(pskey.name, pskey.arguments),
							Name:            pskey.name,
							Arguments:       pskey.arguments,
							Connections:     slices.Collect(maps.Values(psval.connections)),
							InInitTree:      wrapperspb.Bool(psval.inInitTree),
							SyscallInfo:     psval.syscalls,
							ExecIds:         psval.execIDs,
							ExecutionCount:  psval.execCount,
							ExitCount:       psval.exitCount,
							FirstStartTime:  MaybeTimeToTimestamp(psval.firstStartTime),
							LatestStartTime: MaybeTimeToTimestamp(psval.latestStartTime),
							LatestExitTime:  MaybeTimeToTimestamp(psval.latestExitTime),
						}
						result.ApplicationModel.Host.Processes = append(result.ApplicationModel.Host.Processes, ps)
					}
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
					Uid:  wlkey.uid,
				}
				for contkey, contval := range wlval {
					cont := &appModelV1.ApplicationContainer{
						Id:    contkey.cont.Id,
						Name:  contkey.cont.Name,
						Image: contkey.cont.Image,
					}
					for pskey, psval := range contval {
						ps := &appModelV1.ApplicationProcessGroup{
							Hash:            processGroupHash(pskey.name, pskey.arguments),
							Name:            pskey.name,
							Arguments:       pskey.arguments,
							Connections:     slices.Collect(maps.Values(psval.connections)),
							InInitTree:      wrapperspb.Bool(psval.inInitTree),
							SyscallInfo:     psval.syscalls,
							ExecIds:         psval.execIDs,
							ExecutionCount:  psval.execCount,
							ExitCount:       psval.exitCount,
							FirstStartTime:  MaybeTimeToTimestamp(psval.firstStartTime),
							LatestStartTime: MaybeTimeToTimestamp(psval.latestStartTime),
							LatestExitTime:  MaybeTimeToTimestamp(psval.latestExitTime),
						}
						cont.Processes = append(cont.Processes, ps)
					}
					wl.Containers = append(wl.Containers, cont)
				}
				ns.Workloads = append(ns.Workloads, wl)
			}
			result.ApplicationModel.Namespaces = append(result.ApplicationModel.Namespaces, ns)
		}
	}
	// Sort the resulting ApplicationModel.
	EnsureSorted(result.ApplicationModel)
	return result
}

func ProcessModelToApplicationModel(processModel []*types.ProcessModel, nsFilter map[string]bool, nodeLabels map[string]string) *appModelV1.ApplicationModelEvent {
	appModel, _ := ProcessModelToApplicationModelWithProcessData(processModel, nsFilter, nodeLabels)
	return appModel
}

// ProcessModelToApplicationModelWithProcessData converts process models to an application model
// and also returns the process monitor data for building telemetry maps.
func ProcessModelToApplicationModelWithProcessData(processModel []*types.ProcessModel, nsFilter map[string]bool, nodeLabels map[string]string) (*appModelV1.ApplicationModelEvent, ProcessMonitorData) {
	monitor, processes := ConvertToMonitorData(processModel, true)
	nsMap := make(namespaceMap)
	for key, val := range monitor {
		handleNetworkEvent(nsMap, key, val)
	}
	for key, val := range processes {
		handleProcessEvent(nsMap, key, val)
	}
	appModel := namespaceMapToApplicationModel(nsMap, nsFilter)
	appModel.NodeLabels = nodeLabels
	return appModel, processes
}

// Given an ApplicationModelEvent, split it into multiple smaller
// ApplicationModelFragments. The split could eventually be dynamic, but for now:
// 1. Host processes are split into their own event(s) in chunks of 100
//    (configurable) process groups.
// 2. Each workload is split into its own event.

func SplitApplicationModelEvent(appModel *appModelV1.ApplicationModelEvent) []*appModelV1.ApplicationModelFragment {
	hostProcessesPerEvent := eeOption.Config.ApplicationModelSplitMaxHostProcs
	var result []*appModelV1.ApplicationModelFragment

	// Split host processes into chunks of hostProcessesPerEvent
	if appModel.ApplicationModel.GetHost() != nil {
		hostProcesses := appModel.ApplicationModel.Host.GetProcesses()
		for i := 0; i < len(hostProcesses); i += hostProcessesPerEvent {
			end := min(i+hostProcessesPerEvent, len(hostProcesses))
			hostFragment := &appModelV1.ApplicationModelFragment{
				ApplicationModelFragment: &appModelV1.ApplicationModel{
					Id: appModel.ApplicationModel.Id,
					Host: &appModelV1.ApplicationHost{
						Processes: hostProcesses[i:end],
					},
				},
				NodeName:    appModel.NodeName,
				ClusterName: appModel.ClusterName,
				Time:        appModel.Time,
				NodeLabels:  appModel.NodeLabels,
			}
			result = append(result, hostFragment)
		}
	}

	for _, ns := range appModel.ApplicationModel.GetNamespaces() {
		for _, wl := range ns.GetWorkloads() {
			wlFragment := &appModelV1.ApplicationModelFragment{
				ApplicationModelFragment: &appModelV1.ApplicationModel{
					Id: appModel.ApplicationModel.Id,
					Namespaces: []*appModelV1.ApplicationNamespace{
						{
							Name: ns.GetName(),
							Workloads: []*appModelV1.ApplicationWorkload{
								{
									Name:       wl.GetName(),
									Kind:       wl.GetKind(),
									Uid:        wl.GetUid(),
									Containers: wl.GetContainers(),
								},
							},
						},
					},
				},
				NodeName:    appModel.NodeName,
				ClusterName: appModel.ClusterName,
				Time:        appModel.Time,
				NodeLabels:  appModel.NodeLabels,
			}
			result = append(result, wlFragment)
		}
	}

	// It could be possible, although unlikely, that the original ApplicationModelEvent
	// had no host processes and no workloads, resulting in an empty result.
	// In that case, return a copy of the original event.
	if len(result) == 0 {
		return []*appModelV1.ApplicationModelFragment{
			&appModelV1.ApplicationModelFragment{
				ClusterName: appModel.ClusterName,
				NodeName:    appModel.NodeName,
				Time:        appModel.Time,
				NodeLabels:  appModel.NodeLabels,
				ApplicationModelFragment: &appModelV1.ApplicationModel{
					Id:         appModel.ApplicationModel.Id,
					Namespaces: []*appModelV1.ApplicationNamespace{},
					Host:       &appModelV1.ApplicationHost{Processes: []*appModelV1.ApplicationProcessGroup{}},
				},
				FragmentTotal: 1,
				FragmentIndex: 1,
			},
		}
	}

	// Now that we have the result length, set fragment_total/fragment_index.
	for i := range result {
		result[i].FragmentTotal = uint64(len(result))
		result[i].FragmentIndex = uint64(i) + 1 // 1-indexed
	}

	return result
}

// Given a list of ApplicationModelFragments that represent the same application
// model, merge them into a single ApplicationModelEvent. This is essentially
// the inverse of SplitApplicationModelEvent.
func MergeApplicationModelFragments(fragments []*appModelV1.ApplicationModelFragment) (*appModelV1.ApplicationModelEvent, error) {
	var appModelId string

	if len(fragments) == 0 {
		return nil, fmt.Errorf("fragments must be non-empty")
	}

	// Set appModelId to the first id. All the remaining ids must be non-empty and the same.
	for _, m := range fragments {
		if m.ApplicationModelFragment == nil {
			return nil, fmt.Errorf("nil ApplicationModelFragment")
		} else if m.ApplicationModelFragment.Id == "" {
			return nil, fmt.Errorf("empty ApplicationModelFragment.Id")
		} else if appModelId == "" {
			appModelId = m.ApplicationModelFragment.Id
		} else if m.ApplicationModelFragment.Id != appModelId {
			return nil, fmt.Errorf("mismatched ApplicationModelFragment ids")
		}
	}

	// There should be exactly fragment_total fragments.
	if len(fragments) != int(fragments[0].FragmentTotal) {
		return nil, fmt.Errorf("number of fragments does not match FragmentTotal")
	}

	result := &appModelV1.ApplicationModelEvent{
		ApplicationModel: &appModelV1.ApplicationModel{
			Id: appModelId,
		},
		NodeName:    fragments[0].NodeName,
		ClusterName: fragments[0].ClusterName,
		Time:        fragments[0].Time,
		NodeLabels:  fragments[0].NodeLabels,
	}
	nsMap := make(map[string]*appModelV1.ApplicationNamespace)
	for _, m := range fragments {
		for _, ns := range m.ApplicationModelFragment.GetNamespaces() {
			if existing, ok := nsMap[ns.GetName()]; ok {
				existing.Workloads = append(existing.Workloads, ns.GetWorkloads()...)
			} else {
				nsMap[ns.GetName()] = &appModelV1.ApplicationNamespace{
					Name:      ns.GetName(),
					Workloads: ns.GetWorkloads(),
				}
			}
		}
		if m.ApplicationModelFragment.Host != nil {
			if result.ApplicationModel.Host == nil {
				result.ApplicationModel.Host = &appModelV1.ApplicationHost{
					Processes: m.ApplicationModelFragment.Host.Processes,
				}
			} else {
				result.ApplicationModel.Host.Processes = append(result.ApplicationModel.Host.Processes, m.ApplicationModelFragment.Host.Processes...)
			}
		}
	}

	// For consistency, sort namespaces in result
	nsNames := make([]string, 0, len(nsMap))
	for name := range nsMap {
		nsNames = append(nsNames, name)
	}
	sort.Strings(nsNames)

	for _, nsName := range nsNames {
		result.ApplicationModel.Namespaces = append(result.ApplicationModel.Namespaces, nsMap[nsName])
	}
	return result, nil
}

// TelemetryMap maps process keys (name + args) to their aggregated telemetry info.
// We reuse ProcessValue since it already contains all the fields we need.
type TelemetryMap map[string]*ProcessValue

// BuildTelemetryMap creates a map from process key to telemetry info from process monitor data.
// This is used for telemetry export to avoid redundant calls to ConvertToMonitorData.
func BuildTelemetryMap(processData ProcessMonitorData) TelemetryMap {
	result := make(TelemetryMap)

	for processKey, processValue := range processData {
		key := processKey.Name + processKey.Args
		pv := processValue // Create a copy to take address of
		result[key] = &pv
	}
	return result
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
			for _, cont := range wl.GetContainers() {
				for _, ps := range cont.GetProcesses() {
					pmk := ProcessKey{
						Namespace:    ns.GetName(),
						WorkloadKind: wl.GetKind(),
						WorkloadName: wl.GetName(),
						WorkloadUID:  wl.GetUid(),
						Container: types.ContainerInfo{
							Id:    cont.GetId(),
							Name:  cont.GetName(),
							Image: cont.GetImage(),
						},
						Name: ps.GetName(),
						Args: ps.GetArguments(),
					}
					pmd[pmk] = ProcessValue{ExecIDs: ps.GetExecIds()}
					for _, conn := range ps.GetConnections() {
						resourceType := v1alpha.ResourceKind_RESOURCE_KIND_UNSPECIFIED
						if wl.GetKind() != v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED {
							resourceType = v1alpha.ResourceKind_RESOURCE_KIND_WORKLOAD
						}
						nmk := NetworkKey{
							SourceNamespace:            ns.GetName(),
							SourceWorkloadKind:         wl.GetKind(),
							SourceWorkloadResourceKind: resourceType,
							SourceWorkloadName:         wl.GetName(),
							SourceContainer: types.ContainerInfo{
								Id:    cont.GetId(),
								Name:  cont.GetName(),
								Image: cont.GetImage(),
							},
							SourceProcessName: ps.GetName(),
							SourceProcessArgs: ps.GetArguments(),
						}
						addDestinationInfoAppModel(conn.Destination, conn.GetProtocol(), conn.GetObservationPoint(), &nmk)
						nmd[nmk] = NetworkMonitorValue{
							TXBytes: conn.Stats.TxBytes,
							RXBytes: conn.Stats.RxBytes,
						}
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
		pmd[pmk] = ProcessValue{ExecIDs: ps.GetExecIds()}
		for _, conn := range ps.GetConnections() {
			nmk := NetworkKey{
				SourceNamespace:    HostNamespace,
				SourceWorkloadKind: v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
				SourceWorkloadName: HostWorkload,
				SourceProcessName:  ps.GetName(),
				SourceProcessArgs:  ps.GetArguments(),
			}
			addDestinationInfoAppModel(conn.Destination, conn.GetProtocol(), conn.GetObservationPoint(), &nmk)
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
