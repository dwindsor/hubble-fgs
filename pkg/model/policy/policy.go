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

func AddUnsafeNetworkPolicy(policyUID string, policy *types.TetragonNetworkPolicy) error {
	// There are a few possibilities for possible scope.
	// 0. MatchLabels is set then we use this otherwise,
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if len(policy.Subject.MatchLabelsEqual) > 0 {
		return dns.AddMatchLabelNetworkPolicy(policyUID, policy)
	}
	if policy.Subject.Workload.Name != "" && policy.Subject.Workload.Kind != "" {
		return dns.AddNetworkPolicy(policy, false)
	}
	if (policy.Subject.Workload.Name == "" && policy.Subject.Workload.Kind != "") ||
		(policy.Subject.Workload.Kind == "" && policy.Subject.Workload.Name != "") {
		return fmt.Errorf("qosPolicySpec violation requires workload:kind fully specified")
	}

	if policy.Subject.Workload.Namespace == "" {
		return dns.AddNetworkPolicy(policy, false)
	}

	// Namespaced policy handler
	dns.QueueWorkloadNetworkPolicy(policy)
	allPods, err := podinfo.GetPodInfoOfNS(policy.Subject.Workload.Namespace)
	if err != nil {
		return err
	}
	for _, pod := range allPods {
		policy.Subject.Workload.Kind = pod.WorkloadType.Kind
		policy.Subject.Workload.Name = pod.WorkloadObject.Name
		dns.AddNetworkPolicy(policy, false)
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
