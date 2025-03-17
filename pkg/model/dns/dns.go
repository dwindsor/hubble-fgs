// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package dns

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	queueWl     = make(map[types.TetragonWorkloadNetworkSubject]*types.TetragonNetworkPolicy)
	queueWlLock = sync.Mutex{}

	// Destination match labels
	matchLabelDstPolicy     matchLabels.PolicyList = make(map[string]*matchLabels.LabelSet)
	queueMatchLabelsDstLock                        = sync.Mutex{}

	// Global Match Label policy
	matchLabelPolicy     matchLabels.PolicyList = make(map[string]*matchLabels.LabelSet)
	queueMatchLabelsLock                        = sync.Mutex{}

	// Programmer for BPF dataplane
	prog datapath.Interface = &datapath.BpfProgrammer{}
)

func createPodEndpoint(pod *v1alpha1.PodInfo) *endpoint.Endpoint {
	return &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Namespace: pod.WorkloadObject.Namespace,
		Name:      pod.WorkloadObject.Name,
		Kind:      pod.WorkloadType.Kind,
	}
}

func createPodSrcKey(pod *v1alpha1.PodInfo) (*types.ProcessTreeKey, error) {
	return createSrcKey(pod.WorkloadObject.Namespace, pod.WorkloadObject.Name, pod.WorkloadType.Kind)
}

// Top level handler to remove pod: performance bouns, this op requires 2 matchLabel
// policy collections. So we have:
//
//	len(matchLabelPolicy) * [ hash lookup per label ] +
//	len(matchDstLabelPolicy) * [ hash lookup per label ]
//
// So we are scaling with the hash operation and (2 * # policy * avg(label length)
// roughly. Run ./go test --test.bench -test.run BenchPodRemove to get a real idea.
func PodRemove(pod *v1alpha1.PodInfo, local bool) (int, error) {
	var records []*record.DatapathRecord

	ml := &matchLabels.LabelSet{
		Label: pod.ObjectMeta.Labels,
	}

	// Remove datapath entries with {subjects} -> pod. This requires two steps
	// similar to above but done in the other direction. Find the collection of
	// endpoint match labels with the pod as an endpoint. In this case we have
	// singleton endpoint to a set of subjects, endpoint -> {collectionSubjects}.
	// To clear datapath walk the collection of subjects and remove s_i -> endpoint.
	dests := matchLabelDstPolicy.Collection(ml)
	if dests != nil {
		podEP := createPodEndpoint(pod)
		for _, d := range dests {
			s := matchLabelPolicy[d.Name]
			for _, subject := range s.Subjects {
				records = append(records, &record.DatapathRecord{
					Src: subject,
					EP:  podEP,
				})
			}
			for i, ep := range d.Endpoints {
				if *ep == *podEP {
					d.Endpoints = append(d.Endpoints[:i], d.Endpoints[i+1:]...)
					break
				}
			}
		}
	}

	if !local {
		return prog.RemoveRecords(records)
	}

	// Remove datapath entries with pod -> dsts. This requires two steps.
	// First, find collection of subject match labels that belong to this pod.
	// Each subject match label will have map from singleton subject s to a
	// set of endpoints, s -> {collectionEPs}. To clear datapath walk the
	// collection of eps and remove the s->ep_i entry. We can remove the
	// entire instances of the matchLabelSet because the subject is being
	// removed.
	coll := matchLabelPolicy.Collection(ml)
	if coll == nil {
		return prog.RemoveRecords(records)
	}
	subject, err := createPodSrcKey(pod)
	if err != nil {
		return prog.RemoveRecords(records)
	}

	for _, s := range coll {
		d := matchLabelDstPolicy[s.Name]
		for _, ep := range d.Endpoints {
			records = append(records, &record.DatapathRecord{
				Src: subject,
				EP:  ep,
			})
		}
		for i, subj := range s.Subjects {
			if *subj == *subject {
				s.Subjects = append(s.Subjects[:i], s.Subjects[i+1:]...)
				break
			}
		}
		if s.Policy.Default.EnforceAction != nil {
			// Action is not part of the default action key so we just need Src field
			records = append(records, &record.DatapathRecord{
				Src: subject,
				EP:  nil,
			})
		}

		if s.Policy.Destination.FQDN == nil {
			continue
		}

		for _, entry := range s.Policy.Destination.FQDN.Names {
			ep := &endpoint.Endpoint{
				Type: endpoint.DnsType,
				Dns:  entry,
			}
			records = append(records, &record.DatapathRecord{
				Src: subject,
				EP:  ep,
			})
		}
	}
	return prog.RemoveRecords(records)
}

func EndpointAdd(ep *endpoint.Endpoint, ml *matchLabels.LabelSet) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}
	dests := matchLabelDstPolicy.Collection(ml)

	for _, d := range dests {
		// Add endpoint of pod to list of destinations for this label selector
		d.AddEndpoint(ep)

		// For dest dest label selector we need to create src->dst binding
		// to do this walk all subjects and add the new dst. Merge conflicts
		// are resolved by BPF datapath.
		for _, subject := range matchLabelPolicy[d.Name].Subjects {
			// TBD cache this in subject
			action, err := calculateAction(&d.Policy.Action)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("policyName", d.Name).WithField("action", d.Policy.Action).Warn("could not calcluate actions, skipping action")
				continue
			}
			records = append(records, &record.DatapathRecord{
				Src:    subject,
				EP:     ep,
				Action: action,
			})
		}
	}
	return records
}

func SrcAdd(src *types.ProcessTreeKey, ml *matchLabels.LabelSet) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}
	subjects := matchLabelPolicy.Collection(ml)

	for _, s := range subjects {
		s.AddSubject(src)
		// Merge step for cases where s -> {D1->A1} and s -> {D1->A2}
		sRecords, err := AddSrcPolicy(src, s.Policy, true)
		if err != nil {
			logger.GetLogger().WithField("src", src).WithError(err).Warn("ProgAddNetwork failed")
		}
		records = append(records, sRecords...)
	}

	return records
}

func __PodAdd(epPod *v1alpha1.PodInfo, local bool) ([]*record.DatapathRecord, error) {
	ml := &matchLabels.LabelSet{
		Label: epPod.ObjectMeta.Labels,
	}

	ep := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
		Kind:      epPod.WorkloadType.Kind,
	}

	epRecords := EndpointAdd(ep, ml)

	if !local {
		return epRecords, nil
	}

	// tbd fold this into policy xlate layer
	if err := checkWorkloadQuotaPolicy(epPod); err != nil {
		return epRecords, err
	}

	src, err := createPodSrcKey(epPod)
	if err != nil {
		return epRecords, err
	}
	// This is a hard error if the pod was added we must know its namespace for a
	// src ID otherwise we are in a bad state.
	if src == nil {
		return epRecords, fmt.Errorf("unknown or corrupt state, pod has unresolved src identity")
	}

	srcRecords := SrcAdd(src, ml)
	return append(epRecords, srcRecords...), nil
}

// Top level handler to add pod and calculate tetragon network policy
func PodAdd(epPod *v1alpha1.PodInfo, local bool) error {
	records, err := __PodAdd(epPod, local)
	if err != nil {
		return err
	}
	return prog.AddRecords(records)
}

func checkWorkloadQuotaPolicy(epPod *v1alpha1.PodInfo) error {
	subject := types.TetragonWorkloadNetworkSubject{
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
		Kind:      epPod.WorkloadType.Kind,
	}

	queueWlLock.Lock()
	policy, ok := queueWl[subject]
	if !ok {
		/* Check for Namespace policy */
		namespaceSubject := types.TetragonWorkloadNetworkSubject{
			Namespace: subject.Namespace,
			Kind:      "",
			Name:      "",
		}
		policy, ok = queueWl[namespaceSubject]
		if !ok {
			queueWlLock.Unlock()
			return nil
		}
	} else {
		delete(queueWl, subject)
	}
	queueWlLock.Unlock()
	return AddNetworkPolicy(policy, true)
}
