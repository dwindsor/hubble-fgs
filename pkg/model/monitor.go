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

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/google/go-cmp/cmp"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/isovalent/ipa/common/k8s/type/v1alpha"
	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/common"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func prettyWorkloadKind(kind v1alpha.WorkloadKind) string {
	caser := cases.Title(language.English)
	return caser.String(strings.TrimPrefix(kind.String(), "WORKLOAD_KIND_"))
}

func prettyWorkloadResourceKind(kind v1alpha.ResourceKind) string {
	caser := cases.Title(language.English)
	return caser.String(strings.TrimPrefix(kind.String(), "WORKLOAD_RESOURCE_KIND_"))
}

func prettyWorkloadDestination(kind v1alpha.WorkloadKind, resourceKind v1alpha.ResourceKind) string {
	if resourceKind != v1alpha.ResourceKind_RESOURCE_KIND_UNSPECIFIED {
		return prettyWorkloadResourceKind(resourceKind)
	}
	return prettyWorkloadKind(kind)
}

type NetworkKey struct {
	SourceNamespace            string
	SourceWorkloadKind         v1alpha.WorkloadKind
	SourceWorkloadResourceKind v1alpha.ResourceKind
	SourceWorkloadName         string
	SourceWorkloadUID          string
	SourceContainer            types.ContainerInfo
	SourceProcessName          string
	SourceProcessArgs          string
	DestinationPort            uint32
	Protocol                   commonNetV1.IPProtocol
	ObservationPoint           appModelV1.ObservationPoint
	// DNS
	DestinationNames string
	// IP
	DestinationIP string
	// Workload
	DestinationWorkloadName      string
	DestinationWorkloadNamespace string
	DestinationWorkloadKind      v1alpha.WorkloadKind
	DestinationResourceKind      v1alpha.ResourceKind
	DestinationWorkloadUID       string
}

func DestinationName(nk *NetworkKey) string {
	var name string

	// Preamble
	if nk.DestinationWorkloadName != "" {
		name = fmt.Sprintf("%s/%s:%s",
			nk.DestinationWorkloadNamespace,
			prettyWorkloadDestination(nk.DestinationWorkloadKind, nk.DestinationResourceKind),
			nk.DestinationWorkloadName)
	} else if nk.DestinationNames != "" {
		name = nk.DestinationNames
	} else if nk.DestinationIP != "" {
		name = nk.DestinationIP
	}

	// Port
	if nk.DestinationPort != 0 {
		name = fmt.Sprintf("%s:%d", name, nk.DestinationPort)
	}

	return name
}

func (nk NetworkKey) String() string {
	var source, destination string
	if nk.SourceNamespace == HostNamespace {
		source = "host"
	} else {
		source = fmt.Sprintf("%s/%s:%s %s", nk.SourceNamespace, prettyWorkloadKind(nk.SourceWorkloadKind), nk.SourceWorkloadName, nk.SourceContainer)
	}
	destination = DestinationName(&nk)
	return fmt.Sprintf("%s > %s", source, destination)
}

type NetworkMonitorValue struct {
	RuleName              string
	PolicyName            string
	TXBytes               uint64
	RXBytes               uint64
	TXDefaultAllowBytes   uint64
	TXDefaultDropBytes    uint64
	TXDropBytes           uint64
	Sessions              uint64
	TXDefaultAllowPackets uint64
	TXDefaultDropPackets  uint64
	TXDropPackets         uint64
	RXDropBytes           uint64
	RXDropPackets         uint64
	RXDefaultDropBytes    uint64
	RXDefaultDropPackets  uint64
	RXDefaultAllowBytes   uint64
	RXDefaultAllowPackets uint64
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
	policy := ""
	if nmv.PolicyName != "" {
		policy = fmt.Sprintf("%s:%s ", nmv.PolicyName, nmv.RuleName)
	}
	return fmt.Sprintf("%s%s sent %s received %s/%dpkts dropped", policy, getByteSize(nmv.TXBytes), getByteSize(nmv.RXBytes), getByteSize(nmv.TXDropBytes), nmv.TXDropPackets)
}

type byteCounter interface {
	GetPolicy() string
	GetRule() string
	GetTxBytes() uint64
	GetRxBytes() uint64
	GetTxDefaultAllowBytes() uint64
	GetTxDefaultDropBytes() uint64
	GetTxDropBytes() uint64
	GetTxDefaultAllowPackets() uint64
	GetTxDefaultDropPackets() uint64
	GetTxDropPackets() uint64
	GetRxDropBytes() uint64
	GetRxDropPackets() uint64
	GetRxDefaultDropBytes() uint64
	GetRxDefaultDropPackets() uint64
	GetRxDefaultAllowBytes() uint64
	GetRxDefaultAllowPackets() uint64
	GetSessions() uint64
}

func (nmv NetworkMonitorValue) GetPolicy() string {
	return nmv.PolicyName
}

func (nmv NetworkMonitorValue) GetRule() string {
	return nmv.RuleName
}

func (nmv NetworkMonitorValue) GetTxBytes() uint64 {
	return nmv.TXBytes
}

func (nmv NetworkMonitorValue) GetRxBytes() uint64 {
	return nmv.RXBytes
}

func (nmv NetworkMonitorValue) GetTxDefaultAllowBytes() uint64 {
	return nmv.TXDefaultAllowBytes
}

func (nmv NetworkMonitorValue) GetTxDefaultDropBytes() uint64 {
	return nmv.TXDefaultDropBytes
}

func (nmv NetworkMonitorValue) GetTxDropBytes() uint64 {
	return nmv.TXDropBytes
}

func (nmv NetworkMonitorValue) GetTxDefaultAllowPackets() uint64 {
	return nmv.TXDefaultAllowPackets
}

func (nmv NetworkMonitorValue) GetTxDefaultDropPackets() uint64 {
	return nmv.TXDefaultDropPackets
}

func (nmv NetworkMonitorValue) GetTxDropPackets() uint64 {
	return nmv.TXDropPackets
}

func (nmv NetworkMonitorValue) GetRxDropBytes() uint64 {
	return nmv.RXDropBytes
}

func (nmv NetworkMonitorValue) GetRxDropPackets() uint64 {
	return nmv.RXDropPackets
}

func (nmv NetworkMonitorValue) GetRxDefaultDropBytes() uint64 {
	return nmv.RXDefaultDropBytes
}

func (nmv NetworkMonitorValue) GetRxDefaultDropPackets() uint64 {
	return nmv.RXDefaultDropPackets
}

func (nmv NetworkMonitorValue) GetRxDefaultAllowBytes() uint64 {
	return nmv.RXDefaultAllowBytes
}

func (nmv NetworkMonitorValue) GetRxDefaultAllowPackets() uint64 {
	return nmv.RXDefaultAllowPackets
}

func (nmv NetworkMonitorValue) GetSessions() uint64 {
	return nmv.Sessions
}

type NetworkMonitorData map[NetworkKey]NetworkMonitorValue
type ProcessMonitorData map[ProcessKey]ProcessValue

type ProcessKey struct {
	Namespace    string
	WorkloadKind v1alpha.WorkloadKind
	WorkloadName string
	WorkloadUID  string
	Container    types.ContainerInfo
	Name         string
	Args         string
}

type ProcessValue struct {
	InInitTree      bool
	Syscalls        *appModelV1.ApplicationSyscalls
	Parents         []string // All unique immediate parent names for this binary/args tuple
	ExecIDs         []string
	FirstStartTime  *time.Time
	LatestStartTime *time.Time
	LatestExitTime  *time.Time
	ExecCount       uint64
	ExitCount       uint64
}

func (pk ProcessKey) String() string {
	if pk.Namespace == HostNamespace {
		return fmt.Sprintf("host %s %s", pk.Name, pk.Args)
	}
	return fmt.Sprintf("%s/%s:%s %s %s %s", pk.Namespace, prettyWorkloadKind(pk.WorkloadKind), pk.WorkloadName, pk.Container, pk.Name, pk.Args)
}

func (nmd NetworkMonitorData) Print() {
	keys := slices.Collect(maps.Keys(nmd))
	slices.SortFunc(keys, CompareNetworkKeys)
	for _, key := range keys {
		fmt.Println(key, nmd[key])
	}
}

func getNetworkMonitorKey(process *types.ProcessModel, dst *types.Destination, includeProcess bool) NetworkKey {
	nwKey := NetworkKey{
		SourceNamespace: process.Namespace,
	}
	if process.Workload != nil {
		nwKey.SourceWorkloadName = process.Workload.Name
		nwKey.SourceWorkloadUID = process.Workload.UID
		nwKey.SourceWorkloadKind = translateWorkloadKind(process.Workload.Kind)
		if nwKey.SourceWorkloadKind != v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED {
			nwKey.SourceWorkloadResourceKind = v1alpha.ResourceKind_RESOURCE_KIND_WORKLOAD
		}

		if process.Container != nil {
			nwKey.SourceContainer.Id = process.Container.Id
			nwKey.SourceContainer.Name = process.Container.Name
			nwKey.SourceContainer.Image = process.Container.Image
		}
	}
	if includeProcess {
		nwKey.SourceProcessName = process.Binary
		nwKey.SourceProcessArgs = process.BinaryArgs
	}
	addDestinationInfo(dst, &nwKey)
	return nwKey
}

// addDestinationInfo adds destination information from a [tetragon.Destination] to a [NetworkKey].
func addDestinationInfo(dst *types.Destination, nwKey *NetworkKey) {
	if len(dst.DestinationNames) > 0 {
		if len(dst.DestinationNames) == 1 {
			nwKey.DestinationNames = dst.DestinationNames[0]
		} else {
			nwKey.DestinationNames = strings.Join(dst.DestinationNames, ",")
		}
	}
	// Pod and Service can have its own DestinationNames
	// https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
	if dst.DestinationPod != nil {
		nwKey.DestinationWorkloadName = dst.DestinationPod.Workload
		nwKey.DestinationWorkloadNamespace = dst.DestinationPod.Namespace
		nwKey.DestinationWorkloadKind = translateWorkloadKind(dst.DestinationPod.WorkloadKind)
		nwKey.DestinationResourceKind = v1alpha.ResourceKind_RESOURCE_KIND_WORKLOAD
		nwKey.DestinationWorkloadUID = dst.DestinationPod.WorkloadUID
	} else if dst.DestinationService != nil {
		nwKey.DestinationWorkloadName = dst.DestinationService.Name
		nwKey.DestinationWorkloadNamespace = dst.DestinationService.Namespace
		nwKey.DestinationResourceKind = v1alpha.ResourceKind_RESOURCE_KIND_SERVICE
		nwKey.DestinationWorkloadUID = dst.DestinationService.UID
	}

	nwKey.DestinationIP = dst.DestinationIP

	nwKey.DestinationPort = dst.Port
	nwKey.Protocol = commonNetV1.IPProtocol(dst.Protocol)
	nwKey.ObservationPoint = appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE
	if dst.ObservedAtDestination {
		nwKey.ObservationPoint = appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION
	}
}

// addDestinationInfoAppModel adds destination information from a [appModelV1.Destination] to a [NetworkKey].
func addDestinationInfoAppModel(dst *appModelV1.Destination, protocol commonNetV1.IPProtocol, observationPoint appModelV1.ObservationPoint, nwKey *NetworkKey) {
	switch dt := dst.Type.(type) {
	case *appModelV1.Destination_Dns:
		nwKey.DestinationNames = strings.Join(dt.Dns.DestinationNames, ",")
	case *appModelV1.Destination_Ip:
		nwKey.DestinationIP = dt.Ip.Ip
	case *appModelV1.Destination_Workload:
		nwKey.DestinationWorkloadName = dt.Workload.Name
		nwKey.DestinationWorkloadNamespace = dt.Workload.Namespace
		nwKey.DestinationWorkloadKind = dt.Workload.Kind
		nwKey.DestinationResourceKind = dt.Workload.ResourceKind
		nwKey.DestinationWorkloadUID = dt.Workload.Uid
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", dt))
	}

	nwKey.DestinationPort = uint32(dst.Port)
	nwKey.Protocol = protocol
	// Events written before the observation point existed carry the zero
	// value, which means source.
	if observationPoint == appModelV1.ObservationPoint_OBSERVATION_POINT_UNSPECIFIED {
		observationPoint = appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE
	}
	nwKey.ObservationPoint = observationPoint
}

// nwKeyToDestination creates an [appModelV1.Destination] corresponding to a [NetworkKey].
func nwKeyToDestination(nwKey *NetworkKey) *appModelV1.Destination {
	res := &appModelV1.Destination{
		Port: uint64(nwKey.DestinationPort),
	}

	if nwKey.DestinationNames != "" {
		res.Type = &appModelV1.Destination_Dns{
			Dns: &appModelV1.DestinationDns{
				DestinationNames: strings.Split(nwKey.DestinationNames, ","),
			},
		}
	} else if nwKey.DestinationIP != "" {
		res.Type = &appModelV1.Destination_Ip{
			Ip: &appModelV1.DestinationIP{
				Ip: nwKey.DestinationIP,
			},
		}
	} else if nwKey.DestinationWorkloadName != "" {
		res.Type = &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:         nwKey.DestinationWorkloadName,
				Namespace:    nwKey.DestinationWorkloadNamespace,
				Kind:         nwKey.DestinationWorkloadKind,
				ResourceKind: nwKey.DestinationResourceKind,
				Uid:          nwKey.DestinationWorkloadUID,
			},
		}
	}

	return res
}

func getProcessMonitorKey(process *types.ProcessModel) ProcessKey {
	var workloadName string
	var workloadKind v1alpha.WorkloadKind
	var workloadUID string

	if process.Workload != nil {
		workloadName = process.Workload.Name
		workloadKind = translateWorkloadKind(process.Workload.Kind)
		workloadUID = process.Workload.UID
	}

	pmKey := ProcessKey{
		Namespace:    process.Namespace,
		WorkloadName: workloadName,
		WorkloadKind: workloadKind,
		WorkloadUID:  workloadUID,
		Name:         process.Binary,
		Args:         process.BinaryArgs,
	}

	if process.Container != nil {
		pmKey.Container.Id = process.Container.Id
		pmKey.Container.Name = process.Container.Name
		pmKey.Container.Image = process.Container.Image
	}

	return pmKey
}

func getSyscallInfo(abi string, syscalls []uint32) (*appModelV1.ApplicationSyscalls, error) {
	syscall_info := &appModelV1.ApplicationSyscalls{}
	for _, syscall := range syscalls {
		name, err := common.GetSyscallName(abi, int(syscall))
		if err != nil {
			return nil, err
		}
		name = "SYS_" + strings.ToUpper(name)
		value, ok := appModelV1.Sys_value[name]
		if !ok {
			return nil, fmt.Errorf("no such syscall defined in protobuf API: %q", name)
		}
		syscall_info.Syscalls = append(syscall_info.Syscalls, appModelV1.Sys(value))
	}
	switch abi {
	case "x64":
		syscall_info.Abi = appModelV1.Abi_ABI_X86_64
	case "arm64":
		syscall_info.Abi = appModelV1.Abi_ABI_ARM64
	default:
		return nil, fmt.Errorf("unsupported arch: %s", abi)
	}
	return syscall_info, nil
}

var warnOnce = false

// processAccumulator collects per-key state across all process entries in a
// single pass, replacing the seven separate maps used by the old two-pass loop.
type processAccumulator struct {
	model           *types.ProcessModel
	parents         map[string]bool
	execIDs         map[string]struct{}
	execCount       uint64
	exitCount       uint64
	firstStartTime  *time.Time
	latestStartTime *time.Time
	latestExitTime  *time.Time
}

func ConvertToMonitorData(processModel []*types.ProcessModel, includeProcess bool) (NetworkMonitorData, ProcessMonitorData) {
	n := len(processModel)
	result := make(NetworkMonitorData, n)
	proc := make(ProcessMonitorData, n)

	// Single pass: accumulate network data and per-key process state together.
	accum := make(map[ProcessKey]*processAccumulator, n)

	for _, process := range processModel {
		processKey := getProcessMonitorKey(process)

		// Accumulate process state.
		acc := accum[processKey]
		if acc == nil {
			acc = &processAccumulator{
				model:   process,
				parents: make(map[string]bool),
				execIDs: make(map[string]struct{}),
			}
			accum[processKey] = acc
		} else {
			acc.model = process
		}
		if process.Parent != "" {
			acc.parents[process.Parent] = true
		}
		for _, execID := range process.ExecIDs {
			if execID != "" {
				acc.execIDs[execID] = struct{}{}
			}
		}
		acc.execCount += process.ExecCount
		acc.exitCount += process.ExitCount
		if process.FirstStartTime != nil {
			if acc.firstStartTime == nil || process.FirstStartTime.Before(*acc.firstStartTime) {
				acc.firstStartTime = process.FirstStartTime
			}
		}
		if process.LatestStartTime != nil {
			if acc.latestStartTime == nil || process.LatestStartTime.After(*acc.latestStartTime) {
				acc.latestStartTime = process.LatestStartTime
			}
		}
		if process.LatestExitTime != nil {
			if acc.latestExitTime == nil || process.LatestExitTime.After(*acc.latestExitTime) {
				acc.latestExitTime = process.LatestExitTime
			}
		}

		// Accumulate network destinations.
		for _, dst := range process.Dest {
			key := getNetworkMonitorKey(process, dst, includeProcess)
			if dst.Port != 0 {
				currentValue := result[key]
				if dst.Stats != nil {
					currentValue.PolicyName = dst.Stats.Policy
					currentValue.RuleName = dst.Stats.RuleName
					currentValue.TXBytes += dst.Stats.TxBytes
					currentValue.RXBytes += dst.Stats.RxBytes
					currentValue.TXDefaultAllowBytes += dst.Stats.DefaultAllowBytes
					currentValue.TXDefaultDropBytes += dst.Stats.DefaultDenyBytes
					currentValue.TXDropBytes += dst.Stats.TxDropBytes
					currentValue.Sessions += dst.Stats.Sessions
					currentValue.TXDefaultAllowPackets += dst.Stats.DefaultAllowPackets
					currentValue.TXDefaultDropPackets += dst.Stats.DefaultDenyPackets
					currentValue.TXDropPackets += dst.Stats.TxDropPackets
					currentValue.RXDropBytes += dst.Stats.RxDropBytes
					currentValue.RXDropPackets += dst.Stats.RxDropPackets
					currentValue.RXDefaultDropBytes += dst.Stats.RxDefaultDropBytes
					currentValue.RXDefaultDropPackets += dst.Stats.RxDefaultDropPackets
					currentValue.RXDefaultAllowBytes += dst.Stats.RxDefaultAllowBytes
					currentValue.RXDefaultAllowPackets += dst.Stats.RxDefaultAllowPackets
				}
				result[key] = currentValue
			}
		}
	}

	for processKey, acc := range accum {
		syscalls, err := getSyscallInfo(acc.model.Abi, acc.model.Syscalls)
		if err != nil {
			if !warnOnce {
				logger.GetLogger().Debug("failed to populate system call data for process", logfields.Error, err)
				warnOnce = true
			}
		}

		parentsList := make([]string, 0, len(acc.parents))
		for parent := range acc.parents {
			parentsList = append(parentsList, parent)
		}
		slices.Sort(parentsList)

		execIDsList := make([]string, 0, len(acc.execIDs))
		for execID := range acc.execIDs {
			execIDsList = append(execIDsList, execID)
		}
		slices.Sort(execIDsList)

		proc[processKey] = ProcessValue{
			InInitTree:      acc.model.InInitTree,
			Syscalls:        syscalls,
			Parents:         parentsList,
			ExecIDs:         execIDsList,
			FirstStartTime:  acc.firstStartTime,
			LatestStartTime: acc.latestStartTime,
			LatestExitTime:  acc.latestExitTime,
			ExecCount:       acc.execCount,
			ExitCount:       acc.exitCount,
		}
	}

	return result, proc
}

func Diff(current, newer NetworkMonitorData) NetworkMonitorData {
	diff := NetworkMonitorData{}
	for newKey, newValue := range newer {
		if currentValue, ok := current[newKey]; ok {
			if !cmp.Equal(currentValue, newValue) {
				diff[newKey] = NetworkMonitorValue{
					PolicyName:            newValue.PolicyName,
					RuleName:              newValue.RuleName,
					TXBytes:               newValue.TXBytes - currentValue.TXBytes,
					RXBytes:               newValue.RXBytes - currentValue.RXBytes,
					TXDropBytes:           newValue.TXDropBytes - currentValue.TXDropBytes,
					TXDefaultAllowBytes:   newValue.TXDefaultAllowBytes - currentValue.TXDefaultAllowBytes,
					TXDefaultDropBytes:    newValue.TXDefaultDropBytes - currentValue.TXDefaultDropBytes,
					Sessions:              newValue.Sessions - currentValue.Sessions,
					TXDropPackets:         newValue.TXDropPackets - currentValue.TXDropPackets,
					TXDefaultAllowPackets: newValue.TXDefaultAllowPackets - currentValue.TXDefaultAllowPackets,
					TXDefaultDropPackets:  newValue.TXDefaultDropPackets - currentValue.TXDefaultDropPackets,
					RXDropBytes:           newValue.RXDropBytes - currentValue.RXDropBytes,
					RXDropPackets:         newValue.RXDropPackets - currentValue.RXDropPackets,
					RXDefaultDropBytes:    newValue.RXDefaultDropBytes - currentValue.RXDefaultDropBytes,
					RXDefaultDropPackets:  newValue.RXDefaultDropPackets - currentValue.RXDefaultDropPackets,
					RXDefaultAllowBytes:   newValue.RXDefaultAllowBytes - currentValue.RXDefaultAllowBytes,
					RXDefaultAllowPackets: newValue.RXDefaultAllowPackets - currentValue.RXDefaultAllowPackets,
				}
			}
		} else {
			diff[newKey] = NetworkMonitorValue{
				PolicyName:            newValue.PolicyName,
				RuleName:              newValue.RuleName,
				TXBytes:               newValue.TXBytes,
				RXBytes:               newValue.RXBytes,
				TXDropBytes:           newValue.TXDropBytes,
				TXDefaultAllowBytes:   newValue.TXDefaultAllowBytes,
				TXDefaultDropBytes:    newValue.TXDefaultDropBytes,
				Sessions:              newValue.Sessions,
				TXDropPackets:         newValue.TXDropPackets,
				TXDefaultAllowPackets: newValue.TXDefaultAllowPackets,
				TXDefaultDropPackets:  newValue.TXDefaultDropPackets,
				RXDropBytes:           newValue.RXDropBytes,
				RXDropPackets:         newValue.RXDropPackets,
				RXDefaultDropBytes:    newValue.RXDefaultDropBytes,
				RXDefaultDropPackets:  newValue.RXDefaultDropPackets,
				RXDefaultAllowBytes:   newValue.RXDefaultAllowBytes,
				RXDefaultAllowPackets: newValue.RXDefaultAllowPackets,
			}
		}
	}
	return diff
}
