package diff

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/pkg/model"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func StatsZero(a *appModelV1.ConnectionStats) bool {
	if a.TxBytes == 0 && a.RxBytes == 0 && a.TxDrops == 0 &&
		a.DefaultDropBytes == 0 && a.DefaultAllowBytes == 0 {
		return true
	}
	return false
}

func StatsDiff(a, b *appModelV1.ConnectionStats) *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:           a.TxBytes - b.TxBytes,
		RxBytes:           a.RxBytes - b.RxBytes,
		TxDrops:           a.TxDrops - b.TxDrops,
		TxQuota:           a.TxQuota,
		TxQuotaUsage:      a.TxQuotaUsage,
		LastQuotaReset:    a.LastQuotaReset,
		NextQuotaReset:    a.NextQuotaReset,
		DefaultDropBytes:  a.DefaultDropBytes - b.DefaultDropBytes,
		DefaultAllowBytes: a.DefaultAllowBytes - b.DefaultAllowBytes,
	}
}

func ConnectionDiff(a, b []*appModelV1.ApplicationConnection) ([]*appModelV1.ApplicationConnection, error) {
	connsDiff := make([]*appModelV1.ApplicationConnection, 0)

	// Its not obvious to me how to key a Connection so it becomes a n^2 op
	// please don't so this too often.
	for _, connA := range a {
		found := false
		for _, connB := range b {
			res := model.CompareDestination(connA.Destination, connB.Destination)
			if res == 0 {
				found = true
				stats := StatsDiff(connA.Stats, connB.Stats)
				diff := &appModelV1.ApplicationConnection{
					Destination: connA.Destination,
					Stats:       stats,
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

func ProcessDiff(a []*appModelV1.ApplicationProcessGroup, b []*appModelV1.ApplicationProcessGroup) ([]*appModelV1.ApplicationProcessGroup, error) {
	psDiff := make([]*appModelV1.ApplicationProcessGroup, 0)
	psB := make(map[string]*appModelV1.ApplicationProcessGroup, len(b))
	for _, p := range b {
		psB[p.Name+p.Arguments] = p
	}

	for _, p := range a {
		b, ok := psB[p.Name+p.Arguments]
		if !ok {
			psDiff = append(psDiff, p)
			continue
		}

		d := &appModelV1.ApplicationProcessGroup{
			Hash:            p.Hash,
			Name:            p.Name,
			Arguments:       p.Arguments,
			Children:        p.Children,    // children are additive so use latest count
			InInitTree:      p.InInitTree,  // this field is likely buggy or at least not well understood
			SyscallInfo:     p.SyscallInfo, // proppage latest syscall and process totals
			ProcessCount:    p.ProcessCount,
			LatestStartTime: p.LatestStartTime, // propagate latest start time
		}

		// What we care about is new connections.
		conns, err := ConnectionDiff(p.Connections, b.Connections)
		if err != nil {
			return nil, err
		}
		if len(conns) > 0 {
			d.Connections = conns
			psDiff = append(psDiff, d)
		}
	}
	return psDiff, nil
}

func WorkloadDiff(a []*appModelV1.ApplicationWorkload, b []*appModelV1.ApplicationWorkload) ([]*appModelV1.ApplicationWorkload, error) {
	wlDiff := make([]*appModelV1.ApplicationWorkload, 0)
	wlB := make(map[string]*appModelV1.ApplicationWorkload, len(b))
	for _, wl := range b {
		wlB[wl.Name] = wl
	}

	for _, wl := range a {
		w, ok := wlB[wl.Name]
		if !ok {
			wlDiff = append(wlDiff, wl)
			continue
		}

		d := &appModelV1.ApplicationWorkload{
			Name: wl.Name,
			Kind: wl.Kind,
		}

		psDiff, err := ProcessDiff(wl.Processes, w.Processes)
		if err != nil {
			return nil, err
		}
		if len(psDiff) > 0 {
			d.Processes = psDiff
			wlDiff = append(wlDiff, d)
		}
	}
	return wlDiff, nil
}

func ApplicationModelDiff(a *appModelV1.ApplicationModel, b *appModelV1.ApplicationModel) (*appModelV1.ApplicationModel, error) {
	nsDiff := make([]*appModelV1.ApplicationNamespace, 0)
	nsB := make(map[string]*appModelV1.ApplicationNamespace, len(b.Namespaces))
	for _, ns := range b.Namespaces {
		nsB[ns.Name] = ns
	}

	for _, ns := range a.Namespaces {
		// If namespace does not exist in B add it to the diff
		b, ok := nsB[ns.Name]
		if !ok {
			nsDiff = append(nsDiff, ns)
			continue
		}

		d := &appModelV1.ApplicationNamespace{}
		d.Name = ns.Name

		wlDiff, err := WorkloadDiff(ns.Workloads, b.Workloads)
		if err != nil {
			return nil, err
		}
		if len(wlDiff) > 0 {
			d.Workloads = wlDiff
			nsDiff = append(nsDiff, d)
		}
	}

	if len(nsDiff) == 0 {
		return nil, nil
	}

	return &appModelV1.ApplicationModel{
		Namespaces: nsDiff,
	}, nil
}

func getType(d *appModelV1.Destination) appModelV1.ApplicationModelDestinationType {
	var t appModelV1.ApplicationModelDestinationType

	switch d.Type.(type) {
	case *appModelV1.Destination_Dns:
		t = appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_DNS
	case *appModelV1.Destination_Ip:
		t = appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_CIDR
	case *appModelV1.Destination_Workload:
		t = appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_KUBERNETES
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", d.Type))
	}

	return t
}

func getDestination(d *appModelV1.Destination) (string, string, string, appModelV1.WorkloadKind) {
	name := ""
	ns := ""
	wlName := ""
	var wlKind appModelV1.WorkloadKind

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

		name = fmt.Sprintf("%s:%s:%s", ns, wlKind, wlName)
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", d.Type))
	}

	return name, ns, wlName, wlKind
}

func ApplicationModelToNetworkFlat(a *appModelV1.ApplicationModel) ([]*appModelV1.ApplicationModelNetworkFlatEntry, error) {
	n := []*appModelV1.ApplicationModelNetworkFlatEntry{}
	node := node.GetNodeNameForExport()
	cluster := option.Config.ClusterName
	time := timestamppb.Now()

	for _, ns := range a.Namespaces {
		for _, wl := range ns.Workloads {
			for _, p := range wl.Processes {
				for _, c := range p.Connections {
					destName, dns, dname, dkind := getDestination(c.Destination)
					dType := getType(c.Destination)

					entry := &appModelV1.ApplicationModelNetworkFlatEntry{
						ClusterName:                       cluster,
						NodeName:                          node,
						EventType:                         appModelV1.ApplicationModelEventType_APPLICATION_MODEL_EVENT_TYPE_NETWORK_CONNECT,
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
						DestinationKubernetesWorkloadKind: dkind.String(),
						DestinationKubernetesWorkloadName: dname,
						TxBytes:                           c.Stats.TxBytes,
						RxBytes:                           c.Stats.RxBytes,
						TxDrops:                           c.Stats.TxDrops,
						DefaultDropBytes:                  c.Stats.DefaultDropBytes,
						DefaultAllowBytes:                 c.Stats.DefaultAllowBytes,
					}
					n = append(n, entry)
				}

			}
		}
	}
	return n, nil
}
