package policy

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

func AddDnsQuotaPolicy(namespace, wl, kind string, names []string, quota, reset string) error {
	// There are a few possibilities for possible scope.
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if wl != "" && kind != "" {
		return dns.AddDnsQuota(namespace, wl, kind, names, quota, reset)
	}
	if (wl == "" && kind != "") || (kind == "" && wl != "") {
		return fmt.Errorf("qosPolicySpec violation requires workload:kind fully specified")
	}

	if namespace == "" {
		return dns.AddDnsQuota(namespace, wl, kind, names, quota, reset)
	}

	// Namespaced policy handler
	nsidWL := policyfilter.NSID{
		Namespace: namespace,
		Workload:  wl,
		Kind:      kind,
	}
	dns.QueueWorkloadQuotaPolicy(nsidWL, names, reset, quota)
	allPods, err := podinfo.GetPodInfoOfNS(namespace)
	if err != nil {
		return err
	}
	for _, pod := range allPods {
		dns.AddDnsQuota(
			pod.WorkloadObject.Namespace,
			pod.WorkloadObject.Name,
			pod.WorkloadType.Kind,
			names,
			quota,
			reset)
	}

	return nil
}

// This is a somewhat lossy operation the BPF side may lose some stats during
// the update. However, this is a heavy operation to remove a quotas so we
// accept it.
func ClearDnsQuota() error {
	var dstVal model.DestinationEndpointValue
	var dstKey model.DestinationEndpointKey

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
