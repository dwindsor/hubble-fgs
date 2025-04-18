package policy

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

func AddUnsafeNetworkPolicy(policyUID string, policy *types.TetragonNetworkPolicy) error {
	s := dns.NewPolicyState()
	dns.SetRealizedState(s)

	s.CreateMatchLabelsPolicy(policyUID, policy)

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
func ClearDnsPolicy(policyUID string, policy *types.TetragonNetworkPolicy) error {
	s := dns.NewPolicyState()

	if len(policy.Subject.Labels.Equal) > 0 {
		return s.RemoveMatchLabelNetworkPolicy(policyUID, policy)
	}
	return s.RemoveNetworkPolicy(policyUID, policy)
}
