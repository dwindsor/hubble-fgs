package policy

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

func AddDnsPolicy(policy *types.TetragonNetworkPolicy) error {
	//	namespace, wl, kind string, names []string, quota, reset string, deny bool) error {
	// There are a few possibilities for possible scope.
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if policy.Subject.Workload != "" && policy.Subject.Kind != "" {
		return dns.AddDns(policy)
	}
	if (policy.Subject.Workload == "" && policy.Subject.Kind != "") ||
		(policy.Subject.Kind == "" && policy.Subject.Workload != "") {
		return fmt.Errorf("qosPolicySpec violation requires workload:kind fully specified")
	}

	if policy.Subject.Namespace == "" {
		return dns.AddDns(policy)
	}

	// Namespaced policy handler
	dns.QueueWorkloadQuotaPolicy(policy)
	allPods, err := podinfo.GetPodInfoOfNS(policy.Subject.Namespace)
	if err != nil {
		return err
	}
	for _, pod := range allPods {
		policy.Subject.Kind = pod.WorkloadType.Kind
		policy.Subject.Workload = pod.WorkloadObject.Name
		dns.AddDns(policy)
	}

	return nil
}

// This is a somewhat lossy operation the BPF side may lose some stats during
// the update. However, this is a heavy operation to remove a quotas so we
// accept it.
func ClearDnsPolicy() error {
	var dstVal types.DestinationEndpointValue
	var dstKey types.DestinationEndpointKey

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open destination endpoint map")
		return err
	}
	defer dstMap.Close()

	iter := dstMap.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		if dstVal.TxLimit == 0 {
			continue
		}

		dstVal.TxLimit = 0

		if err := dstMap.Update(dstKey, dstVal, 0); err != nil {
			return err
		}
	}
	return nil
}
