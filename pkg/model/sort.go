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

// Sorting implementations for repeated application model fields.

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
)

func EnsureSorted(model *appModelV1.ApplicationModel) {
	if model.Host != nil {
		sortProcessGroups(model.Host.Processes)
	}
	slices.SortFunc(model.Namespaces, func(a, b *appModelV1.ApplicationNamespace) int {
		return cmp.Compare(a.Name, b.Name)
	})
	for _, ns := range model.Namespaces {
		slices.SortFunc(ns.Workloads, func(a, b *appModelV1.ApplicationWorkload) int {
			if res := cmp.Compare(a.Name, b.Name); res != 0 {
				return res
			}
			return cmp.Compare(a.Kind, b.Kind)
		})
		for _, wl := range ns.Workloads {
			slices.SortFunc(wl.Containers, func(a, b *appModelV1.ApplicationContainer) int {
				if res := cmp.Compare(a.Id, b.Id); res != 0 {
					return res
				}
				if res := cmp.Compare(a.Name, b.Name); res != 0 {
					return res
				}
				return cmp.Compare(a.Image, b.Image)
			})
			for _, cont := range wl.Containers {
				sortProcessGroups(cont.Processes)
			}
		}
	}
}

func sortProcessGroups(procs []*appModelV1.ApplicationProcessGroup) {
	slices.SortFunc(procs, func(a, b *appModelV1.ApplicationProcessGroup) int {
		if res := cmp.Compare(a.Name, b.Name); res != 0 {
			return res
		}
		if res := cmp.Compare(a.Arguments, b.Arguments); res != 0 {
			return res
		}
		return cmp.Compare(a.Hash, b.Hash)
	})
	for _, proc := range procs {
		slices.SortFunc(proc.Connections, CompareConnection)
	}
}

// CompareConnection compares two [appModelV1.ApplicationConnection] by
// destination, protocol, and observation point.
func CompareConnection(a, b *appModelV1.ApplicationConnection) int {
	if res := CompareDestination(a.Destination, b.Destination); res != 0 {
		return res
	}
	if res := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); res != 0 {
		return res
	}
	return cmp.Compare(int32(a.ObservationPoint), int32(b.ObservationPoint))
}

// Stable ordinals for each concrete Destination type variant, used to order
// destinations of different types without allocating. The unset ordinal sorts
// before all known types.
const (
	destinationOrdinalUnset = iota
	destinationOrdinalDNS
	destinationOrdinalIP
	destinationOrdinalWorkload
)

// destinationTypeOrdinal returns a stable integer for each concrete Destination
// type variant.
func destinationTypeOrdinal(t any) int {
	switch t.(type) {
	case *appModelV1.Destination_Dns:
		return destinationOrdinalDNS
	case *appModelV1.Destination_Ip:
		return destinationOrdinalIP
	case *appModelV1.Destination_Workload:
		return destinationOrdinalWorkload
	default:
		return destinationOrdinalUnset
	}
}

// CompareDestination compares two [appModelV1.Destination].
func CompareDestination(a, b *appModelV1.Destination) int {
	res := cmp.Compare(destinationTypeOrdinal(a.Type), destinationTypeOrdinal(b.Type))
	if res != 0 {
		return res
	}
	// NB: It's impossible to have a.Type.(type) != b.Type.(Type) due to the check above
	switch at := a.Type.(type) {
	case *appModelV1.Destination_Dns:
		bt := b.Type.(*appModelV1.Destination_Dns)
		aNames := at.Dns.DestinationNames
		slices.Sort(aNames)
		bNames := bt.Dns.DestinationNames
		slices.Sort(bNames)
		res = cmp.Compare(strings.Join(aNames, ""), strings.Join(bNames, ""))
		if res != 0 {
			return res
		}
	case *appModelV1.Destination_Ip:
		bt := b.Type.(*appModelV1.Destination_Ip)
		ipA, errA := netip.ParseAddr(at.Ip.Ip)
		ipB, errB := netip.ParseAddr(bt.Ip.Ip)
		if errA != nil {
			if errB != nil {
				return 0
			}
			return -1
		}
		if errB != nil {
			return 1
		}
		res = ipA.Compare(ipB)
		if res != 0 {
			return res
		}
	case *appModelV1.Destination_Workload:
		bt := b.Type.(*appModelV1.Destination_Workload)
		res = cmp.Compare(at.Workload.Namespace, bt.Workload.Namespace)
		if res != 0 {
			return res
		}
		res = cmp.Compare(at.Workload.Name, bt.Workload.Name)
		if res != 0 {
			return res
		}
		res = cmp.Compare(at.Workload.Kind.String(), bt.Workload.Kind.String())
		if res != 0 {
			return res
		}
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", a.Type))
	}
	res = cmp.Compare(a.Port, b.Port)
	if res != 0 {
		return res
	}
	return 0
}

// CompareNetworkKeys compares two [NetworkKey].
func CompareNetworkKeys(a, b NetworkKey) int {
	if result := strings.Compare(a.SourceNamespace, b.SourceNamespace); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadKind.String(), b.SourceWorkloadKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadResourceKind.String(), b.SourceWorkloadResourceKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadName, b.SourceWorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceContainer.Id, b.SourceContainer.Id); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceContainer.Name, b.SourceContainer.Name); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceContainer.Image, b.SourceContainer.Image); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceProcessName, b.SourceProcessName); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceProcessArgs, b.SourceProcessArgs); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationNames, b.DestinationNames); result != 0 {
		return result
	}
	ipA, errA := netip.ParseAddr(a.DestinationIP)
	ipB, errB := netip.ParseAddr(b.DestinationIP)
	if errA != nil && errB == nil {
		return -1
	}
	if errB != nil && errA == nil {
		return 1
	}
	if errA == nil && errB == nil {
		result := ipA.Compare(ipB)
		if result != 0 {
			return result
		}
	}
	if result := strings.Compare(a.DestinationWorkloadNamespace, b.DestinationWorkloadNamespace); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationWorkloadName, b.DestinationWorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationWorkloadKind.String(), b.DestinationWorkloadKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationResourceKind.String(), b.DestinationResourceKind.String()); result != 0 {
		return result
	}
	if result := cmp.Compare(a.DestinationPort, b.DestinationPort); result != 0 {
		return result
	}
	if result := cmp.Compare(a.Protocol, b.Protocol); result != 0 {
		return result
	}
	return 0
}

// CompareProcessKeys compares two [ProcessKey].
func CompareProcessKeys(a, b ProcessKey) int {
	if result := strings.Compare(a.Namespace, b.Namespace); result != 0 {
		return result
	}
	if result := cmp.Compare(a.WorkloadKind.String(), b.WorkloadKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.WorkloadName, b.WorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.Container.Id, b.Container.Id); result != 0 {
		return result
	}
	if result := strings.Compare(a.Container.Name, b.Container.Name); result != 0 {
		return result
	}
	if result := strings.Compare(a.Container.Image, b.Container.Image); result != 0 {
		return result
	}
	if result := strings.Compare(a.Name, b.Name); result != 0 {
		return result
	}
	return strings.Compare(a.Args, b.Args)
}
