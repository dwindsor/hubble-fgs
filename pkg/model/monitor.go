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
	SourceProcessName          string
	SourceProcessArgs          string
	DestinationPort            uint64
	// DNS
	DestinationNames string
	// IP
	DestinationIP string
	// Workload
	DestinationWorkloadName      string
	DestinationWorkloadNamespace string
	DestinationWorkloadKind      v1alpha.WorkloadKind
	DestinationResourceKind      v1alpha.ResourceKind
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
		source = fmt.Sprintf("%s/%s:%s", nk.SourceNamespace, prettyWorkloadKind(nk.SourceWorkloadKind), nk.SourceWorkloadName)
	}
	destination = DestinationName(&nk)
	return fmt.Sprintf("%s > %s", source, destination)
}

type NetworkMonitorValue struct {
	RuleName          string
	PolicyName        string
	TXBytes           uint64
	RXBytes           uint64
	AllowDefaultBytes uint64
	DenyDefaultBytes  uint64
	TXDrops           uint64
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
	return fmt.Sprintf("%s%s sent %s received %s dropped", policy, getByteSize(nmv.TXBytes), getByteSize(nmv.RXBytes), getByteSize(nmv.TXDrops))
}

type NetworkQuotaValue struct {
	TXBytes           uint64
	RXBytes           uint64
	AllowDefaultBytes uint64
	DenyDefaultBytes  uint64
	TXDrops           uint64
	TXQuota           uint64
	TXUsage           uint64
	LastReset         time.Time
	NextReset         time.Time
}

type byteCounter interface {
	GetPolicy() string
	GetRule() string
	GetTxBytes() uint64
	GetRxBytes() uint64
	GetAllowDefaultBytes() uint64
	GetDenyDefaultBytes() uint64
	GetTxDrops() uint64
	GetTxQuota() uint64
	GetTxUsage() uint64
	GetLastReset() *time.Time
	GetNextReset() *time.Time
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

func (nmv NetworkMonitorValue) GetAllowDefaultBytes() uint64 {
	return nmv.AllowDefaultBytes
}

func (nmv NetworkMonitorValue) GetDenyDefaultBytes() uint64 {
	return nmv.DenyDefaultBytes
}

func (nmv NetworkMonitorValue) GetTxDrops() uint64 {
	return nmv.TXDrops
}

func (NetworkMonitorValue) GetTxQuota() uint64 {
	return 0
}

func (NetworkMonitorValue) GetTxUsage() uint64 {
	return 0
}

func (NetworkMonitorValue) GetLastReset() *time.Time {
	return nil
}

func (NetworkMonitorValue) GetNextReset() *time.Time {
	return nil
}

func (nqv NetworkQuotaValue) GetTxBytes() uint64 {
	return nqv.TXBytes
}

func (nqv NetworkQuotaValue) GetRxBytes() uint64 {
	return nqv.RXBytes
}

func (nqv NetworkQuotaValue) GetTxDrops() uint64 {
	return nqv.TXDrops
}

func (nqv NetworkQuotaValue) GetTxQuota() uint64 {
	return nqv.TXQuota
}

func (nqv NetworkQuotaValue) GetTxUsage() uint64 {
	return nqv.TXUsage
}

func (nqv NetworkQuotaValue) GetLastReset() *time.Time {
	x := nqv.LastReset
	return &x
}

func (nqv NetworkQuotaValue) GetNextReset() *time.Time {
	x := nqv.NextReset
	return &x
}

func (nqv NetworkQuotaValue) String() string {
	now := time.Now()
	var reset string
	if now.Before(nqv.NextReset) {
		reset = fmt.Sprintf("reset in %s", nqv.NextReset.Sub(now).Truncate(time.Second))
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
	WorkloadKind v1alpha.WorkloadKind
	WorkloadName string
	Name         string
	Args         string
}

type ProcessValue struct {
	InInitTree      bool
	Syscalls        *appModelV1.ApplicationSyscalls
	Parents         []string // All unique immediate parent names for this binary/args tuple
	FirstStartTime  *time.Time
	LatestStartTime *time.Time
	LatestExitTime  *time.Time
}

func (pk ProcessKey) String() string {
	if pk.Namespace == HostNamespace {
		return fmt.Sprintf("host %s %s", pk.Name, pk.Args)
	}
	return fmt.Sprintf("%s/%s:%s %s %s", pk.Namespace, prettyWorkloadKind(pk.WorkloadKind), pk.WorkloadName, pk.Name, pk.Args)
}

func (nmd NetworkMonitorData) Print() {
	keys := slices.Collect(maps.Keys(nmd))
	slices.SortFunc(keys, CompareNetworkKeys)
	for _, key := range keys {
		fmt.Println(key, nmd[key])
	}
}

func (nqd NetworkQuotaData) Print() {
	for key, val := range nqd {
		fmt.Println(key, val)
	}
}

func getNetworkMonitorKey(process *types.ProcessModel, dst *types.Destination, includeProcess bool) NetworkKey {
	nwKey := NetworkKey{
		SourceNamespace: process.Namespace,
	}
	if process.Workload != nil {
		nwKey.SourceWorkloadName = process.Workload.Name
		nwKey.SourceWorkloadKind = translateWorkloadKind(process.Workload.Kind)
		if nwKey.SourceWorkloadKind != v1alpha.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED {
			nwKey.SourceWorkloadResourceKind = v1alpha.ResourceKind_RESOURCE_KIND_WORKLOAD
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
	} else if dst.DestinationService != nil {
		nwKey.DestinationWorkloadName = dst.DestinationService.Name
		nwKey.DestinationWorkloadNamespace = dst.DestinationService.Namespace
		nwKey.DestinationResourceKind = v1alpha.ResourceKind_RESOURCE_KIND_SERVICE
	}

	nwKey.DestinationPort = dst.Port
}

// addDestinationInfoAppModel adds destination information from a [appModelV1.Destination] to a [NetworkKey].
func addDestinationInfoAppModel(dst *appModelV1.Destination, nwKey *NetworkKey) {
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
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", dt))
	}

	nwKey.DestinationPort = dst.Port
}

// nwKeyToDestination creates an [appModelV1.Destination] corresponding to a [NetworkKey].
func nwKeyToDestination(nwKey *NetworkKey) *appModelV1.Destination {
	res := &appModelV1.Destination{
		Port: nwKey.DestinationPort,
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
			},
		}
	}

	return res
}

func getProcessMonitorKey(process *types.ProcessModel) ProcessKey {
	var workloadName string
	var workloadKind v1alpha.WorkloadKind

	if process.Workload != nil {
		workloadName = process.Workload.Name
		workloadKind = translateWorkloadKind(process.Workload.Kind)
	}

	return ProcessKey{
		Namespace:    process.Namespace,
		WorkloadName: workloadName,
		WorkloadKind: workloadKind,
		Name:         process.Binary,
		Args:         process.BinaryArgs,
	}
}

func getNetworkQuotaValue(dst *types.Destination) NetworkQuotaValue {
	return NetworkQuotaValue{
		TXBytes:           dst.Stats.TxBytes,
		RXBytes:           dst.Stats.RxBytes,
		AllowDefaultBytes: dst.Stats.DefaultAllowBytes,
		DenyDefaultBytes:  dst.Stats.DefaultDenyBytes,
		TXDrops:           dst.Stats.TxDrops,
		TXQuota:           dst.Stats.TxLimit,
		TXUsage:           dst.Stats.TxQuota,
		NextReset:         dst.Stats.KtimeTxReset.AsTime(),
		LastReset:         dst.Stats.KtimeLastReset.AsTime(),
	}
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

func ConvertToMonitorData(processModel []*types.ProcessModel, includeProcess bool) (NetworkMonitorData, NetworkQuotaData, ProcessMonitorData) {

	result := NetworkMonitorData{}
	quota := NetworkQuotaData{}
	proc := ProcessMonitorData{}

	// Track unique parents for each process key
	processParents := make(map[ProcessKey]map[string]bool)

	// First pass: collect all parents and network data
	for _, process := range processModel {
		processKey := getProcessMonitorKey(process)

		// Initialize parents map for this process key if not exists
		if _, ok := processParents[processKey]; !ok {
			processParents[processKey] = make(map[string]bool)
		}

		// Add parent to the set if it exists
		if process.Parent != "" {
			processParents[processKey][process.Parent] = true
		}

		// Handle network destinations
		for _, dst := range process.Dest {
			key := getNetworkMonitorKey(process, dst, includeProcess)
			if dst.Port != 0 {
				if _, ok := result[key]; !ok {
					result[key] = NetworkMonitorValue{}
				}
				currentValue := result[key]
				if dst.Stats != nil {
					currentValue.PolicyName = dst.Stats.Policy
					currentValue.RuleName = dst.Stats.RuleName
					currentValue.TXBytes += dst.Stats.TxBytes
					currentValue.RXBytes += dst.Stats.RxBytes
					currentValue.AllowDefaultBytes += dst.Stats.DefaultAllowBytes
					currentValue.DenyDefaultBytes += dst.Stats.DefaultDenyBytes
					currentValue.TXDrops += dst.Stats.TxDrops
				}
				result[key] = currentValue
			} else if process.Binary == "" && dst.Stats != nil && dst.Stats.TxLimit > 0 {
				// This is quota-related stats.
				quota[key] = getNetworkQuotaValue(dst)
			}
		}
	}

	// Second pass: create ProcessValue entries with aggregated parents
	processInfoMap := make(map[ProcessKey]*types.ProcessModel)
	for _, process := range processModel {
		processKey := getProcessMonitorKey(process)
		processInfoMap[processKey] = process
	}

	for processKey, process := range processInfoMap {
		syscalls, err := getSyscallInfo(process.Abi, process.Syscalls)
		if err != nil {
			if !warnOnce {
				logger.GetLogger().Debug("failed to populate system call data for process", logfields.Error, err)
				warnOnce = true
			}
		}

		// Convert parents map to sorted slice
		parentsList := make([]string, 0, len(processParents[processKey]))
		for parent := range processParents[processKey] {
			parentsList = append(parentsList, parent)
		}
		slices.Sort(parentsList)

		proc[processKey] = ProcessValue{
			InInitTree:      process.InInitTree,
			Syscalls:        syscalls,
			Parents:         parentsList,
			FirstStartTime:  process.FirstStartTime,
			LatestStartTime: process.LatestStartTime,
			LatestExitTime:  process.LatestExitTime,
		}
	}

	return result, quota, proc
}

func Diff(current, newer NetworkMonitorData) NetworkMonitorData {
	diff := NetworkMonitorData{}
	for newKey, newValue := range newer {
		if currentValue, ok := current[newKey]; ok {
			if !cmp.Equal(currentValue, newValue) {
				diff[newKey] = NetworkMonitorValue{
					PolicyName: newValue.PolicyName,
					RuleName:   newValue.RuleName,
					TXBytes:    newValue.TXBytes - currentValue.TXBytes,
					RXBytes:    newValue.RXBytes - currentValue.RXBytes,
					TXDrops:    newValue.TXDrops - currentValue.TXDrops,
				}
			}
		} else {
			diff[newKey] = NetworkMonitorValue{
				PolicyName: newValue.PolicyName,
				RuleName:   newValue.RuleName,
				TXBytes:    newValue.TXBytes,
				RXBytes:    newValue.RXBytes,
				TXDrops:    newValue.TXDrops,
			}
		}
	}
	return diff
}
