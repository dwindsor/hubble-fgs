// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package dns

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

const (
	InternalFirewallName = "_firewall"
	InternalHostName     = "_host"
	InternalLabelKey     = "_internal"
)

var (
	RealizedState *PolicyState
	DesiredState  *PolicyState
	// Programmer for dataplane default to BPF
	prog datapath.Interface = &datapath.BpfProgrammer{}
)

// Legacy policy is handled as global state
var (
	queueWl     = make(map[types.TetragonWorkloadNetworkSubject]*types.TetragonNetworkPolicy)
	queueWlLock = sync.Mutex{}
)

// At init we build an empty realized state
func init() {
	s := NewPolicyState()
	SetRealizedState(s)
}

func SetDatapath(dp datapath.Interface) {
	prog = dp
}

// Legacy policy add for quotas
func checkWorkloadQuotaPolicy(endpointObject metav1.Object) error {
	var s types.TetragonWorkloadNetworkSubject
	switch o := endpointObject.(type) {
	case *v1alpha1.PodInfo:
		s.Name = o.WorkloadObject.Name
		s.Namespace = o.WorkloadObject.Namespace
		s.Kind = o.WorkloadType.Kind
	case *corev1.Node:
		s.Name = endpointObject.GetName()
		s.Namespace = endpointObject.GetNamespace()
		s.Kind = o.Kind
	default:
		return fmt.Errorf("object %s has unsupported type", o.GetName())
	}

	queueWlLock.Lock()
	policy, ok := queueWl[s]
	if !ok {
		/* Check for Namespace policy */
		namespaceSubject := types.TetragonWorkloadNetworkSubject{
			Namespace: s.Namespace,
			Kind:      "",
			Name:      "",
		}
		policy, ok = queueWl[namespaceSubject]
		if !ok {
			queueWlLock.Unlock()
			return nil
		}
	} else {
		delete(queueWl, s)
	}
	queueWlLock.Unlock()
	return AddNetworkPolicy(policy, true)
}

func createObjectEndpoint(object metav1.Object) *endpoint.Endpoint {
	var ep endpoint.Endpoint

	switch o := object.(type) {
	case *v1alpha1.PodInfo:
		// For Pods, we use the metadata of the top level workload
		// that created the object so that they represent one endpoint
		ep.Type = tetragon.EndpointType_ENDPOINT_TYPE_POD
		ep.Name = o.WorkloadObject.Name
		ep.Namespace = o.WorkloadObject.Namespace
		ep.Kind = o.WorkloadType.Kind
	case *corev1.Node:
		ep.Type = tetragon.EndpointType_ENDPOINT_TYPE_NODE
		ep.Name = object.GetName()
		ep.Namespace = object.GetNamespace()
		ep.Kind = o.Kind
	default:
		ep.Type = tetragon.EndpointType_ENDPOINT_TYPE_UNKNOWN
		ep.Name = object.GetName()
		ep.Namespace = object.GetNamespace()
	}

	return &ep
}

func createObjectSrcKey(object metav1.Object) (*types.ProcessTreeKey, error) {
	var name, namespace, kind string
	switch o := object.(type) {
	case *v1alpha1.PodInfo:
		// For Pods, we use the metadata of the top level workload
		// that created the object so that they represent one source
		name = o.WorkloadObject.Name
		namespace = o.WorkloadObject.Namespace
		kind = o.WorkloadType.Kind
	case *corev1.Node:
		name = object.GetName()
		namespace = object.GetNamespace()
		kind = o.Kind
	default:
		return nil, fmt.Errorf("object %s has unsupported type", o.GetName())
	}
	return createSrcKey(namespace, name, kind)
}

func GetRealizedState() *PolicyState {
	return RealizedState
}

func GetDesiredState() *PolicyState {
	return DesiredState
}

type PolicyState struct {
	// Policy objects organized by qualifier
	Dst matchLabels.PolicyList
	Src matchLabels.PolicyList
	L3  matchLabels.PolicyList

	// Objects in the system, these are pods, nodes, logical networks, etc.
	localObjects     map[k8stypes.UID]metav1.Object
	remoteObjects    map[k8stypes.UID]metav1.Object
	networkL3Objects map[string]uint32
	// TBD networkL2Objects map[uint32]bool

	DstLock sync.Mutex
	SrcLock sync.Mutex
	L3Lock  sync.Mutex

	Reader sync.RWMutex
}

func NewPolicyState() *PolicyState {
	s := &PolicyState{}
	s.Dst = make(map[string]*matchLabels.LabelSet)
	s.Src = make(map[string]*matchLabels.LabelSet)
	s.L3 = make(map[string]*matchLabels.LabelSet)

	s.localObjects = make(map[k8stypes.UID]metav1.Object)
	// Initialize the new state with a local object representing the host
	// itself as a Node with a special label
	s.localObjects[InternalHostName] = &corev1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind: "Node",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   InternalHostName,
			Labels: map[string]string{InternalLabelKey: InternalHostName},
		},
	}

	s.remoteObjects = make(map[k8stypes.UID]metav1.Object)
	s.networkL3Objects = make(map[string]uint32)

	s.DstLock = sync.Mutex{}
	s.SrcLock = sync.Mutex{}
	s.L3Lock = sync.Mutex{}

	s.Reader = sync.RWMutex{}
	return s
}

func SetRealizedState(s *PolicyState) {
	RealizedState = s
}

func (state *PolicyState) DestroyState() {
	state.Dst = nil
	state.Src = nil

	state.localObjects = nil
	state.remoteObjects = nil
}

// Top level handler to remove pod: performance bouns, this op requires 2 matchLabel
// policy collections. So we have:
//
//	len(state.Src) * [ hash lookup per label ] +
//	len(state.Dst) * [ hash lookup per label ]
//
// So we are scaling with the hash operation and (2 * # policy * avg(label length)
// roughly. Run ./go test --test.bench -test.run BenchPodRemove to get a real idea.
func (state *PolicyState) podRemove(pod *v1alpha1.PodInfo) ([]*record.DatapathRecord, error) {
	var records []*record.DatapathRecord

	policy := record.Policy{
		Name: "", // empty name on Remove is OK.
	}

	ml := &matchLabels.LabelSet{
		Labels: pod.Labels,
	}

	// Remove datapath entries with {subjects} -> pod. This requires two steps
	// similar to above but done in the other direction. Find the collection of
	// endpoint match labels with the pod as an endpoint. In this case we have
	// singleton endpoint to a set of subjects, endpoint -> {collectionSubjects}.
	// To clear datapath walk the collection of subjects and remove s_i -> endpoint.
	dests := state.Dst.Collection(ml)
	if dests != nil {
		podEP := createObjectEndpoint(pod)
		for _, d := range dests {
			s := state.Src[d.Name]
			action, err := calculateAction(&s.Policy.Action)
			if err != nil {
				logger.GetLogger().Warn("calculate action failed", logfields.Error, err)
				continue
			}

			ep := record.DatapathEndpoint{
				EP:   podEP,
				Port: 0,
			}

			for _, subject := range s.Subjects {
				for _, process := range s.Policy.Subject.InProcessName {
					self, err := prog.GetBinaryId(process)
					if err != nil {
						logger.GetLogger().Warn("process policy remove error", logfields.Error, err)
						continue
					}

					processSrc := &types.ProcessTreeKey{
						NSID:  subject.NSID,
						Depth: 0,
						Self:  self,
						Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
					}
					records = append(records, &record.DatapathRecord{
						Policy:   policy,
						Src:      processSrc,
						Endpoint: ep,
						Action:   action,
					})
				}
				if len(s.Policy.Subject.InProcessName) == 0 {
					records = append(records, &record.DatapathRecord{
						Policy:   policy,
						Src:      subject,
						Endpoint: ep,
						Action:   action,
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

	_, ok := state.remoteObjects[pod.UID]
	if ok {
		delete(state.remoteObjects, pod.UID)
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

	subject, err := createObjectSrcKey(pod)
	if err != nil {
		return records, nil
	}

	for _, s := range coll {
		action, err := calculateAction(&s.Policy.Action)
		if err != nil {
			logger.GetLogger().Warn("calculate action failed", logfields.Error, err)
			continue
		}
		d := state.Dst[s.Name]
		for _, ep := range d.Endpoints {
			dpEndpoint := record.DatapathEndpoint{
				EP: ep,
			}

			if len(s.Policy.Subject.InProcessName) == 0 {
				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					Src:      subject,
					Endpoint: dpEndpoint,
					Action:   action,
				})
			}
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := prog.GetBinaryId(process)
				if err != nil {
					logger.GetLogger().Warn("pod remove endpoint binary id error", logfields.Error, err)
					continue
				}
				processSrc := &types.ProcessTreeKey{
					NSID:  subject.NSID,
					Depth: 0,
					Self:  self,
					Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
				}
				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					Src:      processSrc,
					Endpoint: dpEndpoint,
					Action:   action,
				})
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
				Policy: policy,
				Src:    subject,
				Endpoint: record.DatapathEndpoint{
					EP:   nil,
					Port: 0,
				},
			})
		}

		if s.Policy.Destination.CIDR != nil {
			r, err := state.addDestCIDRRecords(
				&policy,
				&s.Policy.Destination,
				&s.Policy.Subject,
				subject,
				action)
			if err != nil {
				logger.GetLogger().Warn("PodRemove CIDR records error", logfields.Error, err)
			} else {
				records = append(records, r...)
			}
		}

		if s.Policy.Destination.FQDN == nil {
			continue
		}

		for _, entry := range s.Policy.Destination.FQDN.Names {
			action, err := calculateAction(&s.Policy.Action)
			if err != nil {
				logger.GetLogger().Warn("calculate action failed", logfields.Error, err)
				continue
			}
			ep := &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  entry,
			}
			endpoint := record.DatapathEndpoint{
				EP:   ep,
				Port: 0,
			}
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := prog.GetBinaryId(process)
				if err != nil {
					logger.GetLogger().Warn("pod remove FQDN binary id error", logfields.Error, err)
					continue
				}
				processSrc := &types.ProcessTreeKey{
					NSID:  subject.NSID,
					Depth: 0,
					Self:  self,
					Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
				}

				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					Src:      processSrc,
					Endpoint: endpoint,
					Action:   action,
				})
			}
			if len(s.Policy.Subject.InProcessName) == 0 {
				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					Src:      subject,
					Endpoint: endpoint,
					Action:   action,
				})
			}
		}
	}
	delete(state.localObjects, pod.UID)
	return records, nil
}

func PodRemove(pod *v1alpha1.PodInfo) error {
	state := GetRealizedState()

	state.Reader.RLock()
	defer state.Reader.RUnlock()

	records, err := state.podRemove(pod)
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
		policy := record.Policy{
			Name: policyList.Name,
			Rule: policyList.Policy.Rule,
		}
		for _, subject := range policyList.Subjects {
			action, err := calculateAction(&policyList.Policy.Action)
			if err != nil {
				logger.GetLogger().Warn("could not calcluate actions, skipping action",
					logfields.Error, err, "policyName", d.Name, "action", d.Policy.Action)
				continue
			}

			if len(policyList.Policy.Subject.InProcessName) > 0 {
				for _, process := range policyList.Policy.Subject.InProcessName {
					self, err := prog.GetBinaryId(process)
					if err != nil {
						logger.GetLogger().Warn("process policy remove error", logfields.Error, err)
						continue
					}
					if len(policyList.Policy.Destination.Ports) == 0 {
						endpoint := record.DatapathEndpoint{
							EP:   ep,
							Port: 0,
						}
						processSrc := &types.ProcessTreeKey{
							NSID:  subject.NSID,
							Depth: 0,
							Self:  self,
							Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
						}
						records = append(records, &record.DatapathRecord{
							Policy:   policy,
							Src:      processSrc,
							Endpoint: endpoint,
							Action:   action,
						})
					}
					for _, port := range policyList.Policy.Destination.Ports {
						endpoint := record.DatapathEndpoint{
							EP:   ep,
							Port: port,
						}
						processSrc := &types.ProcessTreeKey{
							NSID:  subject.NSID,
							Depth: 0,
							Self:  self,
							Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
						}
						records = append(records, &record.DatapathRecord{
							Policy:   policy,
							Src:      processSrc,
							Endpoint: endpoint,
							Action:   action,
						})
					}
				}
			} else {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}

				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					Src:      subject,
					Endpoint: endpoint,
					Action:   action,
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
			logger.GetLogger().Warn("ProgAddNetwork failed", logfields.Error, err, "src", src)
		}
		records = append(records, sRecords...)
	}

	return records
}

func getNamespaceLabels(ns string) map[string]string {
	l := make(map[string]string)

	l["kubernetes.io/metadata.name"] = ns
	return l
}

func addNamespaceLabels(endpointObject metav1.Object, ml *matchLabels.LabelSet) error {
	ns := endpointObject.GetNamespace()
	labels := getNamespaceLabels(ns)
	for k, v := range labels {
		tnpKey := fmt.Sprintf("_tnp_%s", k)
		ml.Labels[tnpKey] = v
	}
	return nil
}

// These three functions Add, Get, Delete are meant to be used by NXOS code to
// manage the logical network state.
func (state *PolicyState) AddL3Network(name string, uid uint32) {
	logger.GetLogger().Info("Add Logical Network", "vrf", name, "gid", uid)
	state.networkL3Objects[name] = uid
}

func (state *PolicyState) GetL3NetworkID(name string) uint32 {
	return state.networkL3Objects[name]
}

func (state *PolicyState) DelL3NetworkID(name string) {
	delete(state.networkL3Objects, name)
}

func (state *PolicyState) l3Add(name string) ([]*record.DatapathRecord, error) {
	records := []*record.DatapathRecord{}

	ml := &matchLabels.LabelSet{}
	ml.Labels = make(map[string]string, 1)
	ml.Labels["vrf"] = name

	// Find all policy with key pair vrf:name
	l3s := state.L3.Collection(ml)

	// Generate a record set for each policy we found because each
	// policy includes the full tuple in IP form (we have no
	// labels in middleboxes... yet.).
	for _, l3 := range l3s {
		policy := record.Policy{
			Name: l3.Name,
			Rule: l3.Policy.Rule,
		}

		action, err := calculateAction(&l3.Policy.Action)
		if err != nil {
			logger.GetLogger().Warn("calculate action failed", logfields.Error, err)
			continue
		}

		ep := &endpoint.Endpoint{
			Ip: l3.Policy.Destination.CIDR.CIDR,
		}

		// TBD Support wildcarding destination ports

		// Ports get flattened here. We've so far avoided it at
		// higher level in case we have a datapath that wants to
		// consume an array. So far it hasn't been useful so we
		// might move it up the stack.
		for _, dport := range l3.Policy.Destination.Ports {
			de := &record.DatapathEndpoint{
				EP:   ep,
				Port: uint32(dport),
			}

			ds := &record.DatapathSource{
				Ip:   l3.Policy.Source.CIDR.CIDR,
				Vrf:  l3.Policy.Subject.LogicalNetwork.VRF,
				Vlan: l3.Policy.Subject.LogicalNetwork.VLAN,
			}

			if len(l3.Policy.Source.Ports) == 0 {
				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					L3Src:    *ds,
					Endpoint: *de,
					Action:   action,
				})
			}

			// This is the somewhat odd case of firewalling what
			// would typically be ephemeral ports, but we can
			// allow at least at the policy side.
			for _, sport := range l3.Policy.Source.Ports {
				ds.Port = uint32(sport)
				records = append(records, &record.DatapathRecord{
					Policy:   policy,
					L3Src:    *ds,
					Endpoint: *de,
					Action:   action,
				})
			}
		}
	}
	return records, nil
}

func (state *PolicyState) objectAdd(endpointObject metav1.Object) ([]*record.DatapathRecord, error) {
	ml := &matchLabels.LabelSet{}
	if endpointObject.GetLabels() == nil {
		ml.Labels = make(map[string]string, 1)
	} else {
		ml.Labels = endpointObject.GetLabels()
	}

	addNamespaceLabels(endpointObject, ml)

	ep := createObjectEndpoint(endpointObject)

	epRecords := state.EndpointAdd(ep, ml, true)

	// tbd fold this into policy xlate layer
	if err := checkWorkloadQuotaPolicy(endpointObject); err != nil {
		return epRecords, err
	}

	src, err := createObjectSrcKey(endpointObject)
	if err != nil {
		return epRecords, err
	}

	// If there is no local key it must be a remote pod
	if src == nil {
		state.remoteObjects[endpointObject.GetUID()] = endpointObject
		return epRecords, nil
	}

	srcRecords := state.SrcAdd(src, ml, true)
	state.localObjects[endpointObject.GetUID()] = endpointObject
	return append(epRecords, srcRecords...), nil
}

// Top level handler to add pod and calculate tetragon network policy
func PodAdd(epPod *v1alpha1.PodInfo) error {
	state := GetRealizedState()

	state.Reader.RLock()
	defer state.Reader.RUnlock()

	records, err := state.objectAdd(epPod)
	if err != nil {
		return err
	}

	return prog.AddRecords(records, false)
}
