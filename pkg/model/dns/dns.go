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

	k8stypes "k8s.io/apimachinery/pkg/types"
)

var (
	RealizedState *PolicyState
	DesiredState  *PolicyState
	// Programmer for BPF dataplane
	prog datapath.Interface = &datapath.BpfProgrammer{}
)

// Legacy policy is handled as global state
var (
	queueWl     = make(map[types.TetragonWorkloadNetworkSubject]*types.TetragonNetworkPolicy)
	queueWlLock = sync.Mutex{}
)

// At init we build an empty realized state
func init() {
	s := New()
	SetRealizedState(s)
}

// Legacy policy add for quotas
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

func GetRealizedState() *PolicyState {
	return RealizedState
}

func GetDesiredState() *PolicyState {
	return DesiredState
}

type PolicyState struct {
	Dst matchLabels.PolicyList
	Src matchLabels.PolicyList

	localPods  map[k8stypes.UID]*v1alpha1.PodInfo
	remotePods map[k8stypes.UID]*v1alpha1.PodInfo

	DstLock sync.Mutex
	SrcLock sync.Mutex

	Reader sync.RWMutex
}

func New() *PolicyState {
	s := &PolicyState{}
	s.Dst = make(map[string]*matchLabels.LabelSet)
	s.Src = make(map[string]*matchLabels.LabelSet)

	s.localPods = make(map[k8stypes.UID]*v1alpha1.PodInfo)
	s.remotePods = make(map[k8stypes.UID]*v1alpha1.PodInfo)

	s.DstLock = sync.Mutex{}
	s.SrcLock = sync.Mutex{}

	s.Reader = sync.RWMutex{}
	return s
}

func SetRealizedState(s *PolicyState) {
	RealizedState = s
}

func (state *PolicyState) DestroyState() {
	state.Dst = nil
	state.Src = nil

	state.localPods = nil
	state.remotePods = nil
}

// Top level handler to remove pod: performance bouns, this op requires 2 matchLabel
// policy collections. So we have:
//
//	len(state.Src) * [ hash lookup per label ] +
//	len(state.Dst) * [ hash lookup per label ]
//
// So we are scaling with the hash operation and (2 * # policy * avg(label length)
// roughly. Run ./go test --test.bench -test.run BenchPodRemove to get a real idea.
func (state *PolicyState) __PodRemove(pod *v1alpha1.PodInfo, local bool) ([]*record.DatapathRecord, error) {
	var records []*record.DatapathRecord

	ml := &matchLabels.LabelSet{
		Label: pod.ObjectMeta.Labels,
	}

	// Remove datapath entries with {subjects} -> pod. This requires two steps
	// similar to above but done in the other direction. Find the collection of
	// endpoint match labels with the pod as an endpoint. In this case we have
	// singleton endpoint to a set of subjects, endpoint -> {collectionSubjects}.
	// To clear datapath walk the collection of subjects and remove s_i -> endpoint.
	dests := state.Dst.Collection(ml)
	if dests != nil {
		podEP := createPodEndpoint(pod)
		for _, d := range dests {
			s := state.Src[d.Name]
			for _, subject := range s.Subjects {
				for _, process := range s.Policy.Subject.InProcessName {
					self, err := prog.GetBinaryId(process)
					if err != nil {
						logger.GetLogger().WithError(err).Warn("process policy remove error")
						continue
					}
					subject.Self = self
					records = append(records, &record.DatapathRecord{
						Src: subject,
						EP:  podEP,
					})
					subject.Self = 0
				}
				if len(s.Policy.Subject.InProcessName) == 0 {
					records = append(records, &record.DatapathRecord{
						Src: subject,
						EP:  podEP,
					})
				}
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
		state.remotePods[pod.ObjectMeta.UID] = nil
		return records, nil
	}

	// Remove datapath entries with pod -> dsts. This requires two steps.
	// First, find collection of subject match labels that belong to this pod.
	// Each subject match label will have map from singleton subject s to a
	// set of endpoints, s -> {collectionEPs}. To clear datapath walk the
	// collection of eps and remove the s->ep_i entry. We can remove the
	// entire instances of the matchLabelSet because the subject is being
	// removed.
	coll := state.Src.Collection(ml)
	if coll == nil {
		return records, nil
	}
	subject, err := createPodSrcKey(pod)
	if err != nil {
		return records, nil
	}

	for _, s := range coll {
		d := state.Dst[s.Name]
		for _, ep := range d.Endpoints {
			if len(s.Policy.Subject.InProcessName) == 0 {
				records = append(records, &record.DatapathRecord{
					Src: subject,
					EP:  ep,
				})
			}
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := prog.GetBinaryId(process)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("pod remove endpoint binary id error")
					continue
				}
				subject.Self = self
				records = append(records, &record.DatapathRecord{
					Src: subject,
					EP:  ep,
				})
				subject.Self = 0
			}
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
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := prog.GetBinaryId(process)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("pod remove FQDN binary id error")
					continue
				}
				subject.Self = self

				ep := &endpoint.Endpoint{
					Type: endpoint.DnsType,
					Dns:  entry,
				}
				records = append(records, &record.DatapathRecord{
					Src: subject,
					EP:  ep,
				})
				subject.Self = 0
			}
			if len(s.Policy.Subject.InProcessName) == 0 {
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
	}
	state.localPods[pod.ObjectMeta.UID] = nil
	return records, nil
}

func PodRemove(pod *v1alpha1.PodInfo, local bool) error {
	state := GetRealizedState()

	state.Reader.RLock()
	defer state.Reader.RUnlock()

	records, err := state.__PodRemove(pod, local)
	if err != nil {
		return err
	}
	return prog.RemoveRecords(records)
}

func (state *PolicyState) EndpointAdd(ep *endpoint.Endpoint, ml *matchLabels.LabelSet, newEP bool) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}
	dests := state.Dst.Collection(ml)

	for _, d := range dests {
		// Add endpoint of pod to list of destinations for this label selector
		if newEP {
			d.AddEndpoint(ep)
		}

		// For dest dest label selector we need to create src->dst binding
		// to do this walk all subjects and add the new dst. Merge conflicts
		// are resolved by BPF datapath.
		policyList := state.Src[d.Name]
		for _, subject := range policyList.Subjects {
			action, err := calculateAction(&d.Policy.Action)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("policyName", d.Name).WithField("action", d.Policy.Action).Warn("could not calcluate actions, skipping action")
				subject.Self = 0
				continue
			}

			if len(policyList.Policy.Subject.InProcessName) > 0 {
				for _, process := range policyList.Policy.Subject.InProcessName {
					self, err := prog.GetBinaryId(process)
					if err != nil {
						logger.GetLogger().WithError(err).Warn("process policy remove error")
						continue
					}
					subject.Self = self
					records = append(records, &record.DatapathRecord{
						Src:    subject,
						EP:     ep,
						Action: action,
					})
					subject.Self = 0
				}
			} else {
				records = append(records, &record.DatapathRecord{
					Src:    subject,
					EP:     ep,
					Action: action,
				})
			}
		}
	}
	return records
}

func (state *PolicyState) SrcAdd(src *types.ProcessTreeKey, ml *matchLabels.LabelSet, newSrc bool) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}
	subjects := state.Src.Collection(ml)

	for _, s := range subjects {
		if newSrc {
			s.AddSubject(src)
		}
		sRecords, err := state.AddSrcPolicy(s.Name, src, s.Policy, true)
		if err != nil {
			logger.GetLogger().WithField("src", src).WithError(err).Warn("ProgAddNetwork failed")
		}
		records = append(records, sRecords...)
	}

	return records
}

func (state *PolicyState) __PodAdd(epPod *v1alpha1.PodInfo, local bool) ([]*record.DatapathRecord, error) {
	ml := &matchLabels.LabelSet{
		Label: epPod.ObjectMeta.Labels,
	}

	ep := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
		Kind:      epPod.WorkloadType.Kind,
	}

	epRecords := state.EndpointAdd(ep, ml, true)

	if !local {
		state.remotePods[epPod.ObjectMeta.UID] = epPod
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

	srcRecords := state.SrcAdd(src, ml, true)
	state.localPods[epPod.ObjectMeta.UID] = epPod
	return append(epRecords, srcRecords...), nil
}

// Top level handler to add pod and calculate tetragon network policy
func PodAdd(epPod *v1alpha1.PodInfo, local bool) error {
	state := GetRealizedState()

	state.Reader.RLock()
	defer state.Reader.RUnlock()

	records, err := state.__PodAdd(epPod, local)
	if err != nil {
		return err
	}
	return prog.AddRecords(records)
}
