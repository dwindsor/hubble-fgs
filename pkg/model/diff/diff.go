// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package diff

import (
	"context"
	"fmt"
	"slices"
	"uuid"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	k8sTypes "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"

	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
)

func StatsZero(a *appModelV1.ConnectionStats) bool {
	if a.TxBytes == 0 && a.RxBytes == 0 && a.TxDropBytes == 0 &&
		a.DefaultDropBytes == 0 && a.DefaultAllowBytes == 0 &&
		a.TxDropPackets == 0 && a.DefaultDropPackets == 0 &&
		a.DefaultAllowPackets == 0 &&
		a.RxDropBytes == 0 && a.RxDropPackets == 0 &&
		a.RxDefaultDropBytes == 0 && a.RxDefaultDropPackets == 0 &&
		a.RxDefaultAllowBytes == 0 && a.RxDefaultAllowPackets == 0 &&
		a.Sessions == 0 {
		return true
	}
	return false
}

func StatsDiff(a, b *appModelV1.ConnectionStats) (*appModelV1.ConnectionStats, error) {
	if b.TxBytes > a.TxBytes {
		return nil, fmt.Errorf("stats diff underflow on TxBytes: %d - %d", a.TxBytes, b.TxBytes)
	}
	if b.RxBytes > a.RxBytes {
		return nil, fmt.Errorf("stats diff underflow on RxBytes: %d - %d", a.RxBytes, b.RxBytes)
	}
	if b.TxDropBytes > a.TxDropBytes {
		return nil, fmt.Errorf("stats diff underflow on TxDropBytes: %d - %d", a.TxDropBytes, b.TxDropBytes)
	}
	if b.DefaultDropBytes > a.DefaultDropBytes {
		return nil, fmt.Errorf("stats diff underflow on DefaultDropBytes: %d - %d", a.DefaultDropBytes, b.DefaultDropBytes)
	}
	if b.DefaultAllowBytes > a.DefaultAllowBytes {
		return nil, fmt.Errorf("stats diff underflow on DefaultAllowBytes: %d - %d", a.DefaultAllowBytes, b.DefaultAllowBytes)
	}
	if b.TxDropPackets > a.TxDropPackets {
		return nil, fmt.Errorf("stats diff underflow on TxDropPackets: %d - %d", a.TxDropPackets, b.TxDropPackets)
	}
	if b.DefaultDropPackets > a.DefaultDropPackets {
		return nil, fmt.Errorf("stats diff underflow on DefaultDropPackets: %d - %d", a.DefaultDropPackets, b.DefaultDropPackets)
	}
	if b.DefaultAllowPackets > a.DefaultAllowPackets {
		return nil, fmt.Errorf("stats diff underflow on DefaultAllowPackets: %d - %d", a.DefaultAllowPackets, b.DefaultAllowPackets)
	}
	if b.RxDropBytes > a.RxDropBytes {
		return nil, fmt.Errorf("stats diff underflow on RxDropBytes: %d - %d", a.RxDropBytes, b.RxDropBytes)
	}
	if b.RxDropPackets > a.RxDropPackets {
		return nil, fmt.Errorf("stats diff underflow on RxDropPackets: %d - %d", a.RxDropPackets, b.RxDropPackets)
	}
	if b.RxDefaultDropBytes > a.RxDefaultDropBytes {
		return nil, fmt.Errorf("stats diff underflow on RxDefaultDropBytes: %d - %d", a.RxDefaultDropBytes, b.RxDefaultDropBytes)
	}
	if b.RxDefaultDropPackets > a.RxDefaultDropPackets {
		return nil, fmt.Errorf("stats diff underflow on RxDefaultDropPackets: %d - %d", a.RxDefaultDropPackets, b.RxDefaultDropPackets)
	}
	if b.RxDefaultAllowBytes > a.RxDefaultAllowBytes {
		return nil, fmt.Errorf("stats diff underflow on RxDefaultAllowBytes: %d - %d", a.RxDefaultAllowBytes, b.RxDefaultAllowBytes)
	}
	if b.RxDefaultAllowPackets > a.RxDefaultAllowPackets {
		return nil, fmt.Errorf("stats diff underflow on RxDefaultAllowPackets: %d - %d", a.RxDefaultAllowPackets, b.RxDefaultAllowPackets)
	}
	if b.Sessions > a.Sessions {
		return nil, fmt.Errorf("stats diff underflow on Sessions: %d - %d", a.Sessions, b.Sessions)
	}

	txDropBytes := a.TxDropBytes - b.TxDropBytes
	return &appModelV1.ConnectionStats{
		TxBytes:               a.TxBytes - b.TxBytes,
		RxBytes:               a.RxBytes - b.RxBytes,
		TxDrops:               txDropBytes, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
		TxDropBytes:           txDropBytes,
		TxDropPackets:         a.TxDropPackets - b.TxDropPackets,
		DefaultDropBytes:      a.DefaultDropBytes - b.DefaultDropBytes,
		DefaultAllowBytes:     a.DefaultAllowBytes - b.DefaultAllowBytes,
		DefaultDropPackets:    a.DefaultDropPackets - b.DefaultDropPackets,
		DefaultAllowPackets:   a.DefaultAllowPackets - b.DefaultAllowPackets,
		RxDropBytes:           a.RxDropBytes - b.RxDropBytes,
		RxDropPackets:         a.RxDropPackets - b.RxDropPackets,
		RxDefaultDropBytes:    a.RxDefaultDropBytes - b.RxDefaultDropBytes,
		RxDefaultDropPackets:  a.RxDefaultDropPackets - b.RxDefaultDropPackets,
		RxDefaultAllowBytes:   a.RxDefaultAllowBytes - b.RxDefaultAllowBytes,
		RxDefaultAllowPackets: a.RxDefaultAllowPackets - b.RxDefaultAllowPackets,
		Sessions:              a.Sessions - b.Sessions,
	}, nil
}

func ConnectionDiff(a, b []*appModelV1.ApplicationConnection) ([]*appModelV1.ApplicationConnection, error) {
	connsDiff := make([]*appModelV1.ApplicationConnection, 0)

	// Its not obvious to me how to key a Connection so it becomes a n^2 op
	// please don't so this too often.
	for _, connA := range a {
		found := false
		for _, connB := range b {
			if model.CompareConnection(connA, connB) == 0 {
				found = true
				stats, err := StatsDiff(connA.Stats, connB.Stats)
				if err != nil {
					logger.GetLogger().Warn("skipping connection, stats diff error", "new", connA.String(), "old", connB.String(), logfields.Error, err)
					break
				}

				diff := &appModelV1.ApplicationConnection{
					Destination: connA.Destination,
					Stats:       stats,
					Policy:      connA.Policy,
					Protocol:    connA.Protocol,
				}
				if !StatsZero(diff.Stats) {
					connsDiff = append(connsDiff, diff)
				}
				break
			}
		}
		// new connection
		if !found {
			connsDiff = append(connsDiff, connA)
		}
	}
	return connsDiff, nil
}

func ProcessDiff(a []*appModelV1.ApplicationProcessGroup, b []*appModelV1.ApplicationProcessGroup) ([]*appModelV1.ApplicationProcessGroup, []*appModelV1.ApplicationProcessGroup, error) {
	psDiff := make([]*appModelV1.ApplicationProcessGroup, 0)
	connDiff := make([]*appModelV1.ApplicationProcessGroup, 0)
	psB := make(map[string]*appModelV1.ApplicationProcessGroup, len(b))
	for _, p := range b {
		psB[p.Name+p.Arguments] = p
	}

	for _, p := range a {
		b, ok := psB[p.Name+p.Arguments]
		if !ok {
			// New process - add to diff
			psDiff = append(psDiff, p)
			if len(p.Connections) > 0 {
				connDiff = append(connDiff, p)
			}
			continue
		}

		// Check if process counts or exec IDs changed.
		if (p.ExecutionCount > b.ExecutionCount) || (p.ExitCount > b.ExitCount) || !slices.Equal(p.ExecIds, b.ExecIds) {
			psDiff = append(psDiff, p)
			if len(p.Connections) > 0 {
				connDiff = append(connDiff, p)
			}
			continue
		}

		d := &appModelV1.ApplicationProcessGroup{
			Hash:            p.Hash,
			Name:            p.Name,
			Arguments:       p.Arguments,
			ExecIds:         p.ExecIds,
			Children:        p.Children,    // children are additive so use latest count
			InInitTree:      p.InInitTree,  // this field is likely buggy or at least not well understood
			SyscallInfo:     p.SyscallInfo, // propagate latest syscall and process totals
			ProcessCount:    p.ProcessCount,
			FirstStartTime:  p.FirstStartTime,  // propagate first start time
			LatestStartTime: p.LatestStartTime, // propagate latest start time
			LatestExitTime:  p.LatestExitTime,  // propagate latest exit time
			ExecutionCount:  p.ExecutionCount,
			ExitCount:       p.ExitCount,
		}

		// What we care about is new connections.
		conns, err := ConnectionDiff(p.Connections, b.Connections)
		if err != nil {
			return nil, nil, err
		}
		if len(conns) > 0 {
			d.Connections = conns
			connDiff = append(connDiff, d)
		}
	}
	return connDiff, psDiff, nil
}

func contFilterConns(cont *appModelV1.ApplicationContainer) *appModelV1.ApplicationContainer {
	diff := &appModelV1.ApplicationContainer{
		Id:    cont.Id,
		Name:  cont.Name,
		Image: cont.Image,
	}

	for _, p := range cont.Processes {
		if len(p.Connections) > 0 {
			diff.Processes = append(diff.Processes, p)
		}
	}
	if len(diff.Processes) > 0 {
		return diff
	}
	return nil
}

func ContainerDiff(a []*appModelV1.ApplicationContainer, b []*appModelV1.ApplicationContainer) ([]*appModelV1.ApplicationContainer, []*appModelV1.ApplicationContainer, error) {
	contDiff := make([]*appModelV1.ApplicationContainer, 0)
	connDiff := make([]*appModelV1.ApplicationContainer, 0)
	contB := make(map[string]*appModelV1.ApplicationContainer, len(b))
	for _, cont := range b {
		contB[cont.Id] = cont
	}

	for _, cont := range a {
		c, ok := contB[cont.Id]
		if !ok {
			contDiff = append(contDiff, cont)

			cf := contFilterConns(cont)
			if cf != nil {
				connDiff = append(connDiff, cf)
			}
			continue
		}

		d := &appModelV1.ApplicationContainer{
			Id:    cont.Id,
			Name:  cont.Name,
			Image: cont.Image,
		}

		connContDiff, psDiff, err := ProcessDiff(cont.Processes, c.Processes)
		if err != nil {
			return nil, nil, err
		}
		if len(psDiff) > 0 {
			d.Processes = psDiff
			contDiff = append(contDiff, d)
		}
		if len(connContDiff) > 0 {
			d.Processes = connContDiff
			connDiff = append(connDiff, d)
		}
	}
	return connDiff, contDiff, nil
}

func wlFilterConns(wl *appModelV1.ApplicationWorkload) *appModelV1.ApplicationWorkload {
	diff := &appModelV1.ApplicationWorkload{
		Name: wl.Name,
		Kind: wl.Kind,
		Uid:  wl.Uid,
	}

	for _, cont := range wl.Containers {
		contDiff := contFilterConns(cont)
		if contDiff != nil {
			diff.Containers = append(diff.Containers, contDiff)
		}
	}

	if len(diff.Containers) > 0 {
		return diff
	}

	return nil
}

func nsFilterConns(ns *appModelV1.ApplicationNamespace) *appModelV1.ApplicationNamespace {
	diff := &appModelV1.ApplicationNamespace{
		Name: ns.Name,
	}

	for _, wl := range ns.Workloads {
		wlDiff := wlFilterConns(wl)
		if wlDiff != nil {
			diff.Workloads = append(diff.Workloads, wlDiff)
		}
	}

	if len(diff.Workloads) > 0 {
		return diff
	}
	return nil
}

func WorkloadDiff(a []*appModelV1.ApplicationWorkload, b []*appModelV1.ApplicationWorkload) ([]*appModelV1.ApplicationWorkload, []*appModelV1.ApplicationWorkload, error) {
	wlDiff := make([]*appModelV1.ApplicationWorkload, 0)
	connDiff := make([]*appModelV1.ApplicationWorkload, 0)
	wlB := make(map[string]*appModelV1.ApplicationWorkload, len(b))
	for _, wl := range b {
		wlB[workloadIdentity(wl)] = wl
	}

	for _, wl := range a {
		b, ok := wlB[workloadIdentity(wl)]
		if !ok {
			wlDiff = append(wlDiff, wl)

			wlf := wlFilterConns(wl)
			if wlf != nil {
				connDiff = append(connDiff, wlf)
			}
			continue
		}
		d := &appModelV1.ApplicationWorkload{
			Name: wl.Name,
			Kind: wl.Kind,
			Uid:  wl.Uid,
		}
		connWlDiff, contDiff, err := ContainerDiff(wl.Containers, b.Containers)
		if err != nil {
			return nil, nil, err
		}
		if len(contDiff) > 0 {
			d.Containers = contDiff
			wlDiff = append(wlDiff, d)
		}
		if len(connWlDiff) > 0 {
			d.Containers = connWlDiff
			connDiff = append(connDiff, d)
		}
	}
	return connDiff, wlDiff, nil
}

func workloadIdentity(workload *appModelV1.ApplicationWorkload) string {
	if workload.Uid != "" {
		return workload.Uid
	}
	return workload.Name
}

func ApplicationModelDiff(a *appModelV1.ApplicationModel, b *appModelV1.ApplicationModel) (*appModelV1.ApplicationModel, *appModelV1.ApplicationModel, error) {
	nsProcessDiff := make([]*appModelV1.ApplicationNamespace, 0)
	nsNetworkDiff := make([]*appModelV1.ApplicationNamespace, 0)

	nsB := make(map[string]*appModelV1.ApplicationNamespace, len(b.Namespaces))
	for _, ns := range b.Namespaces {
		nsB[ns.Name] = ns
	}

	for _, ns := range a.Namespaces {
		// If namespace does not exist in B add it to the diff
		b, ok := nsB[ns.Name]
		if !ok {
			nsProcessDiff = append(nsProcessDiff, ns)

			nsf := nsFilterConns(ns)
			if nsf != nil {
				nsNetworkDiff = append(nsNetworkDiff, nsf)
			}
			continue
		}

		d := &appModelV1.ApplicationNamespace{}
		d.Name = ns.Name

		networkDiff, wlDiff, err := WorkloadDiff(ns.Workloads, b.Workloads)
		if err != nil {
			return nil, nil, err
		}
		if len(wlDiff) > 0 {
			d.Workloads = wlDiff
			nsProcessDiff = append(nsProcessDiff, d)
		}
		if len(networkDiff) > 0 {
			d.Workloads = networkDiff
			nsNetworkDiff = append(nsNetworkDiff, d)
		}
	}

	processDiff := make([]*appModelV1.ApplicationProcessGroup, 0)
	networkDiff := make([]*appModelV1.ApplicationProcessGroup, 0)

	if a.Host != nil {
		var err error

		networkDiff, processDiff, err = ProcessDiff(a.Host.Processes, b.Host.Processes)
		if err != nil {
			return nil, nil, err
		}
	}

	var processDiffModel *appModelV1.ApplicationModel
	var networkDiffModel *appModelV1.ApplicationModel

	if len(nsProcessDiff) != 0 || len(processDiff) != 0 {
		processDiffModel = &appModelV1.ApplicationModel{Id: a.Id}

		if len(nsProcessDiff) > 0 {
			processDiffModel.Namespaces = nsProcessDiff
		}
		if len(processDiff) > 0 {
			processDiffModel.Host = &appModelV1.ApplicationHost{
				Processes: processDiff,
			}
		}
	}

	if len(nsNetworkDiff) != 0 || len(networkDiff) != 0 {
		networkDiffModel = &appModelV1.ApplicationModel{Id: a.Id}

		if len(nsNetworkDiff) != 0 {
			networkDiffModel.Namespaces = nsNetworkDiff
		}
		if len(networkDiff) != 0 {
			networkDiffModel.Host = &appModelV1.ApplicationHost{
				Processes: networkDiff,
			}
		}
	}

	return networkDiffModel, processDiffModel, nil
}

func getType(d *appModelV1.Destination) appModelV1.DestinationType {
	var t appModelV1.DestinationType

	switch d.Type.(type) {
	case *appModelV1.Destination_Dns:
		t = appModelV1.DestinationType_DESTINATION_TYPE_DNS
	case *appModelV1.Destination_Ip:
		t = appModelV1.DestinationType_DESTINATION_TYPE_CIDR
	case *appModelV1.Destination_Workload:
		t = appModelV1.DestinationType_DESTINATION_TYPE_KUBERNETES
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", d.Type))
	}

	return t
}

func getDestination(d *appModelV1.Destination) (string, string, string, k8sTypes.WorkloadKind, k8sTypes.ResourceKind) {
	name := ""
	ns := ""
	wlName := ""
	var wlKind k8sTypes.WorkloadKind
	var resourceKind k8sTypes.ResourceKind

	switch at := d.Type.(type) {
	case *appModelV1.Destination_Dns:
		if len(at.Dns.DestinationNames) > 0 {
			name = at.Dns.DestinationNames[0]
		}
	case *appModelV1.Destination_Ip:
		name = at.Ip.Ip
	case *appModelV1.Destination_Workload:
		ns = at.Workload.Namespace
		wlName = at.Workload.Name
		wlKind = at.Workload.Kind
		resourceKind = at.Workload.ResourceKind

		name = fmt.Sprintf("%s:%s:%s", ns, wlKind, wlName)
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", d.Type))
	}

	return name, ns, wlName, wlKind, resourceKind
}

func ApplicationModelToProcessFlat(ctx context.Context, a *appModelV1.ApplicationModel, telemetryMap model.TelemetryMap, nodeMetadata local.MetadataService) ([]*appModelV1.ProcessTelemetry, error) {
	t := []*appModelV1.ProcessTelemetry{}
	node := node.GetNodeNameForExport()
	cluster := option.Config.ClusterName
	currentTime := timestamppb.Now()

	if a == nil {
		return nil, nil
	}

	if telemetryMap == nil {
		telemetryMap = make(model.TelemetryMap)
	}

	labels, err := nodeMetadata.GetLabels(ctx)
	if err != nil {
		logger.GetLogger().Warn("Failed to get node labels. node_labels field will be empty", logfields.Error, err)
	}

	for _, ns := range a.Namespaces {
		for _, wl := range ns.Workloads {
			for _, cont := range wl.Containers {
				for _, p := range cont.Processes {
					processKey := p.Name + p.Arguments
					info := telemetryMap[processKey]

					var parents []string
					var execCount uint64
					var exitCount uint64
					var firstStartTime, latestStartTime *timestamppb.Timestamp
					if info != nil {
						parents = info.Parents
						execCount = info.ExecCount
						exitCount = info.ExitCount
						firstStartTime = model.MaybeTimeToTimestamp(info.FirstStartTime)
						latestStartTime = model.MaybeTimeToTimestamp(info.LatestStartTime)
					}

					entry := &appModelV1.ProcessTelemetry{
						Id:          uuid.New().String(),
						ClusterName: cluster,
						Container: &appModelV1.ApplicationContainer{
							Id:    cont.Id,
							Name:  cont.Name,
							Image: cont.Image,
						},
						NodeName:               node,
						NodeLabels:             labels,
						EventType:              appModelV1.TelemetryType_TELEMETRY_TYPE_PROCESS,
						Time:                   currentTime,
						KubernetesNamespace:    ns.Name,
						KubernetesWorkloadName: wl.Name,
						KubernetesWorkloadKind: wl.Kind,
						ProcessName:            p.Name,
						ProcessArguments:       p.Arguments,
						ProcessHash:            p.Hash,
						ApplicationModelId:     a.Id,
						FirstStartTime:         firstStartTime,
						LatestStartTime:        latestStartTime,
						ParentNames:            parents,
						ExecutionCount:         execCount,
						ExitCount:              exitCount,
					}
					t = append(t, entry)
				}
			}
		}
	}

	if a.Host != nil {
		for _, p := range a.Host.Processes {
			processKey := p.Name + p.Arguments
			info := telemetryMap[processKey]

			var parents []string
			var execCount uint64
			var exitCount uint64
			var firstStartTime, latestStartTime *timestamppb.Timestamp
			if info != nil {
				parents = info.Parents
				execCount = info.ExecCount
				exitCount = info.ExitCount
				firstStartTime = model.MaybeTimeToTimestamp(info.FirstStartTime)
				latestStartTime = model.MaybeTimeToTimestamp(info.LatestStartTime)
			}

			entry := &appModelV1.ProcessTelemetry{
				Id:                 uuid.New().String(),
				ClusterName:        cluster,
				NodeName:           node,
				NodeLabels:         labels,
				EventType:          appModelV1.TelemetryType_TELEMETRY_TYPE_PROCESS,
				Time:               currentTime,
				ProcessName:        p.Name,
				ProcessArguments:   p.Arguments,
				ProcessHash:        p.Hash,
				ApplicationModelId: a.Id,
				FirstStartTime:     firstStartTime,
				LatestStartTime:    latestStartTime,
				ParentNames:        parents,
				ExecutionCount:     execCount,
				ExitCount:          exitCount,
			}
			t = append(t, entry)
		}
	}
	return t, nil
}

func policyVerdict(s *appModelV1.ConnectionStats) appModelV1.PolicyVerdict {
	if s.TxDropBytes > 0 {
		return appModelV1.PolicyVerdict_POLICY_VERDICT_DROP
	}
	if s.DefaultDropBytes > 0 {
		return appModelV1.PolicyVerdict_POLICY_VERDICT_DROP
	}
	if s.DefaultAllowBytes > 0 {
		return appModelV1.PolicyVerdict_POLICY_VERDICT_ALLOW
	}
	// This check must be last because drop bytes will also inc the txbytes
	if s.TxBytes > 0 || s.RxBytes > 0 {
		return appModelV1.PolicyVerdict_POLICY_VERDICT_ALLOW
	}
	return appModelV1.PolicyVerdict_POLICY_VERDICT_UNSPECIFIED
}

func ApplicationModelToNetworkFlat(ctx context.Context, a *appModelV1.ApplicationModel, nodeMetadata local.MetadataService) ([]*appModelV1.NetworkConnectTelemetry, error) {
	n := []*appModelV1.NetworkConnectTelemetry{}
	node := node.GetNodeNameForExport()
	cluster := option.Config.ClusterName
	time := timestamppb.Now()

	if a == nil {
		return nil, nil
	}

	labels, err := nodeMetadata.GetLabels(ctx)
	if err != nil {
		logger.GetLogger().Warn("Application model to network flat failed to get node info. node_labels field will be empty", logfields.Error, err)
	}

	for _, ns := range a.Namespaces {
		for _, wl := range ns.Workloads {
			for _, cont := range wl.Containers {
				for _, p := range cont.Processes {
					for _, c := range p.Connections {
						verdict := appModelV1.PolicyVerdict_POLICY_VERDICT_UNSPECIFIED
						destName, dns, dname, dkind, dres := getDestination(c.Destination)
						dType := getType(c.Destination)

						if c.Policy.PolicyName != "" {
							verdict = policyVerdict(c.Stats)
						}
						entry := &appModelV1.NetworkConnectTelemetry{
							Id:          uuid.New().String(),
							ClusterName: cluster,
							Container: &appModelV1.ApplicationContainer{
								Id:    cont.Id,
								Name:  cont.Name,
								Image: cont.Image,
							},
							NodeName:                          node,
							EventType:                         appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
							Time:                              time,
							KubernetesNamespace:               ns.Name,
							KubernetesWorkloadName:            wl.Name,
							KubernetesWorkloadKind:            wl.Kind,
							ProcessName:                       p.Name,
							ProcessArguments:                  p.Arguments,
							DestinationName:                   destName,
							DestinationType:                   dType,
							DestinationPort:                   uint32(c.Destination.Port),
							DestinationKubernetesNamespace:    dns,
							DestinationKubernetesWorkloadKind: dkind,
							DestinationKubernetesResourceName: dname,
							DestinationKubernetesResourceKind: dres,
							TxBytes:                           c.Stats.TxBytes,
							RxBytes:                           c.Stats.RxBytes,
							TxDrops:                           c.Stats.TxDropBytes, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
							TxDropBytes:                       c.Stats.TxDropBytes,
							TxDropPackets:                     c.Stats.TxDropPackets,
							DefaultDropBytes:                  c.Stats.DefaultDropBytes,
							DefaultAllowBytes:                 c.Stats.DefaultAllowBytes,
							DefaultDropPackets:                c.Stats.DefaultDropPackets,
							DefaultAllowPackets:               c.Stats.DefaultAllowPackets,
							RxDropBytes:                       c.Stats.RxDropBytes,
							RxDropPackets:                     c.Stats.RxDropPackets,
							RxDefaultDropBytes:                c.Stats.RxDefaultDropBytes,
							RxDefaultDropPackets:              c.Stats.RxDefaultDropPackets,
							RxDefaultAllowBytes:               c.Stats.RxDefaultAllowBytes,
							RxDefaultAllowPackets:             c.Stats.RxDefaultAllowPackets,
							Sessions:                          c.Stats.Sessions,
							NodeLabels:                        labels,
							PolicyName:                        c.Policy.PolicyName,
							RuleName:                          c.Policy.RuleName,
							Verdict:                           verdict,
							ApplicationModelId:                a.Id,
							Protocol:                          c.Protocol,
						}
						n = append(n, entry)
					}
				}
			}
		}
	}

	if a.Host != nil {
		for _, p := range a.Host.Processes {
			for _, c := range p.Connections {
				verdict := appModelV1.PolicyVerdict_POLICY_VERDICT_UNSPECIFIED
				destName, dns, dname, dkind, dres := getDestination(c.Destination)
				dType := getType(c.Destination)

				if c.Policy.PolicyName != "" {
					verdict = policyVerdict(c.Stats)
				}

				entry := &appModelV1.NetworkConnectTelemetry{
					Id:                                uuid.New().String(),
					ClusterName:                       cluster,
					NodeName:                          node,
					EventType:                         appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
					Time:                              time,
					ProcessName:                       p.Name,
					ProcessArguments:                  p.Arguments,
					DestinationName:                   destName,
					DestinationType:                   dType,
					DestinationPort:                   uint32(c.Destination.Port),
					DestinationKubernetesNamespace:    dns,
					DestinationKubernetesWorkloadKind: dkind,
					DestinationKubernetesResourceName: dname,
					DestinationKubernetesResourceKind: dres,
					TxBytes:                           c.Stats.TxBytes,
					RxBytes:                           c.Stats.RxBytes,
					TxDrops:                           c.Stats.TxDropBytes, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
					TxDropBytes:                       c.Stats.TxDropBytes,
					TxDropPackets:                     c.Stats.TxDropPackets,
					DefaultDropBytes:                  c.Stats.DefaultDropBytes,
					DefaultAllowBytes:                 c.Stats.DefaultAllowBytes,
					DefaultDropPackets:                c.Stats.DefaultDropPackets,
					DefaultAllowPackets:               c.Stats.DefaultAllowPackets,
					RxDropBytes:                       c.Stats.RxDropBytes,
					RxDropPackets:                     c.Stats.RxDropPackets,
					RxDefaultDropBytes:                c.Stats.RxDefaultDropBytes,
					RxDefaultDropPackets:              c.Stats.RxDefaultDropPackets,
					RxDefaultAllowBytes:               c.Stats.RxDefaultAllowBytes,
					RxDefaultAllowPackets:             c.Stats.RxDefaultAllowPackets,
					Sessions:                          c.Stats.Sessions,
					NodeLabels:                        labels,
					PolicyName:                        c.Policy.PolicyName,
					RuleName:                          c.Policy.RuleName,
					Verdict:                           verdict,
					ApplicationModelId:                a.Id,
					Protocol:                          c.Protocol,
				}
				n = append(n, entry)
			}
		}
	}
	return n, nil
}

func TelemetryToConnection(telemetry *appModelV1.NetworkConnectTelemetry) *graphV1.Connection {
	sResourceType := k8sTypes.ResourceKind_RESOURCE_KIND_UNSPECIFIED
	if telemetry.KubernetesWorkloadKind != k8sTypes.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED {
		sResourceType = k8sTypes.ResourceKind_RESOURCE_KIND_WORKLOAD
	}
	source := &graphV1.Vertex{
		Family: &graphV1.Vertex_Kubernetes{
			Kubernetes: &graphV1.VertexFamilyKubernetes{
				Uid:                  "",
				ResourceVersion:      "",
				ResourceName:         telemetry.KubernetesWorkloadName,
				ResourceKind:         sResourceType,
				ClusterName:          telemetry.ClusterName,
				Namespace:            telemetry.KubernetesNamespace,
				NodeName:             telemetry.NodeName,
				PodName:              "",
				ContainerName:        "",
				ServiceKind:          0,
				WorkloadKind:         telemetry.KubernetesWorkloadKind,
				Ip:                   "",
				IpProtocol:           telemetry.Protocol,
				ApplicationModelUuid: telemetry.ApplicationModelId,
			},
		},
	}

	var destination *graphV1.Vertex
	switch telemetry.DestinationType {
	case appModelV1.DestinationType_DESTINATION_TYPE_KUBERNETES:
		destination = &graphV1.Vertex{
			Family: &graphV1.Vertex_Kubernetes{
				Kubernetes: &graphV1.VertexFamilyKubernetes{
					ResourceKind: telemetry.DestinationKubernetesResourceKind,
					ResourceName: telemetry.DestinationKubernetesResourceName,
					ClusterName:  telemetry.ClusterName,
					Namespace:    telemetry.DestinationKubernetesNamespace,
					ServiceKind:  telemetry.DestinationKubernetesServiceKind,
					WorkloadKind: telemetry.DestinationKubernetesWorkloadKind,
					Port:         telemetry.DestinationPort,
					IpProtocol:   telemetry.Protocol,
				},
			},
		}

	case appModelV1.DestinationType_DESTINATION_TYPE_CIDR:
		destination = &graphV1.Vertex{
			Family: &graphV1.Vertex_WorldEntity{
				WorldEntity: &graphV1.VertexFamilyWorldEntity{
					Ip:         telemetry.DestinationName,
					Port:       telemetry.DestinationPort,
					IpProtocol: telemetry.Protocol,
				},
			},
		}
	case appModelV1.DestinationType_DESTINATION_TYPE_DNS:
		destination = &graphV1.Vertex{
			Family: &graphV1.Vertex_WorldEntity{
				WorldEntity: &graphV1.VertexFamilyWorldEntity{
					DnsName:    telemetry.DestinationName,
					Port:       telemetry.DestinationPort,
					IpProtocol: telemetry.Protocol,
				},
			},
		}
	}

	link := &graphV1.Edge{
		Type: &graphV1.Edge_NetworkTelemetry{
			NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
				NetworkTransmitBytesTotal: telemetry.TxBytes,
				// Each drop total and its policy subset carry the same packet
				// count. The datapath only observes policy drops, so every drop it
				// sees is a policy drop. Interface drops, which would lift a total
				// above its policy subset, are not accounted for yet; that is
				// future work.
				NetworkTransmitDropTotal:       telemetry.TxDropPackets,
				NetworkTransmitDropPolicyTotal: telemetry.TxDropPackets,
				NetworkReceiveBytesTotal:       telemetry.RxBytes,
				NetworkReceiveDropTotal:        telemetry.RxDropPackets,
				NetworkReceiveDropPolicyTotal:  telemetry.RxDropPackets,
			},
		},
	}
	return &graphV1.Connection{
		Source:      source,
		Destination: destination,
		Links:       []*graphV1.Edge{link},
	}
}
