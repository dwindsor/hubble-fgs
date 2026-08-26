// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package netpolstate

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/servicemap"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	InternalHostName = "_host"
	InternalLabelKey = "_internal"
)

// SetK8sReader sets the Kubernetes client reader for namespace lookups
func (state *PolicyState) SetK8sReader(reader client.Reader) {
	state.deps.k8sReader = reader
}

var getState = sync.OnceValue(NewPolicyState)

// Get returns the singleton holding the network policy state.
func Get() *PolicyState {
	return getState()
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

func (deps externalDeps) createObjectSrcKey(object metav1.Object) (*types.ProcessTreeKey, error) {
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
	return deps.createSrcKey(namespace, name, kind)
}

// externalDeps contains the systems we interact with (BPF, K8s, workloadID)
// This provide a clearer separation on the actual state we store (typically
// maps, list) and the operation we need to perform to program the datapath or
// read external information like workloadid or k8s info.
type externalDeps struct {
	// workloadID is to lookup cgroup ID to workload association
	workloadID *workloadid.State
	// Programmer for dataplane default to BPF
	prog datapath.Interface
	// k8sReader is used to read namespace labels from Kubernetes
	k8sReader client.Reader
}

type PolicyState struct {
	// Policy objects organized by qualifier
	dst matchLabels.PolicyList
	src matchLabels.PolicyList

	// Objects in the system, these are pods, nodes etc.
	localObjects  map[k8stypes.UID]metav1.Object
	remoteObjects map[k8stypes.UID]metav1.Object

	serviceSelPolicies map[types.TetragonPolicyUniqueID]*types.TetragonNetworkPolicy

	serviceMap *servicemap.ServiceMap

	// mu naively protects all maps and lists above by locking at the
	// exported methods PodAdd/PodRemove/RemovePolicy/etc. level, the only
	// optimization for now is to release when programming the datapath. If
	// more efficient concurrency is needed, more fine-grained locking could
	// be done.
	mu sync.RWMutex

	deps externalDeps
}

func NewPolicyState() *PolicyState {
	s := &PolicyState{}
	s.dst = make(map[types.TetragonPolicyUniqueID]*matchLabels.LabelSet)
	s.src = make(map[types.TetragonPolicyUniqueID]*matchLabels.LabelSet)

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
			// UID is used as the key for localObjects.
			UID: InternalHostName,
		},
	}

	s.remoteObjects = make(map[k8stypes.UID]metav1.Object)
	s.serviceSelPolicies = make(map[types.TetragonPolicyUniqueID]*types.TetragonNetworkPolicy)

	s.deps = externalDeps{
		workloadID: workloadid.GetState(),
		prog:       &datapath.BPFProgrammer{},
	}

	return s
}

// temporaryEmptyState is a legacy compatibility layer function. We have some
// functions that are operating on a new empty state instead of mutating the
// state in place. This should be removed eventually.
func (state *PolicyState) temporaryEmptyState() *PolicyState {
	s := NewPolicyState()

	// We pass the existing state deps: methods will need them when
	// computing stuff from the empty state
	s.deps = state.deps

	return s
}

// writeToState is a legacy compatibility layer function. We have some functions
// that previously, instead of mutating the state in place, created a new fresh
// state and replaced the old state with it. We now want to keep a singleton
// instance of the state and write to it directly. This should be removed
// eventually when the function will be capable of mutating the state directly.
func (state *PolicyState) writeToState(newState *PolicyState) {
	state.dst = newState.dst
	state.src = newState.src
	state.localObjects = newState.localObjects
	state.remoteObjects = newState.remoteObjects
	state.serviceSelPolicies = newState.serviceSelPolicies
	state.serviceMap = newState.serviceMap
}

// SetServiceMap sets the ServiceMap used for serviceSelector policy lookups.
// This should be called after the ServiceMap is initialized in the manager.
func (state *PolicyState) SetServiceMap(sm *servicemap.ServiceMap) {
	state.serviceMap = sm
}

// GetServiceMap returns the ServiceMap for this PolicyState.
// Returns nil if not set - callers should handle this case.
func (state *PolicyState) GetServiceMap() *servicemap.ServiceMap {
	return state.serviceMap
}

// Top level handler to remove pod: performance bouns, this op requires 2 matchLabel
// policy collections. So we have:
//
//	len(state.Src) * [ hash lookup per label ] +
//	len(state.Dst) * [ hash lookup per label ]
//
// So we are scaling with the hash operation and (2 * # policy * avg(label length)
// roughly. Run ./go test --test.bench -test.run BenchPodRemove to get a real idea.
func (state *PolicyState) podRemove(pod *v1alpha1.PodInfo) ([]record.DatapathRecord, error) {
	var records []record.DatapathRecord

	policy := types.TetragonPolicyUniqueID{} // empty policyUID on Remove is OK.

	ml := &matchLabels.LabelSet{
		Labels: pod.Labels,
	}

	// Remove datapath entries with {subjects} -> pod. This requires two steps
	// similar to above but done in the other direction. Find the collection of
	// endpoint match labels with the pod as an endpoint. In this case we have
	// singleton endpoint to a set of subjects, endpoint -> {collectionSubjects}.
	// To clear datapath walk the collection of subjects and remove s_i -> endpoint.
	dests := state.dst.Collection(ml)
	if dests != nil {
		podEP := createObjectEndpoint(pod)
		for _, d := range dests {
			s := state.src[d.Policy.PolicyUID]
			action := calculateAction(&s.Policy.Action)

			ep := record.DatapathEndpoint{
				EP:   podEP,
				Port: 0,
			}

			for _, subject := range s.Subjects {
				for _, process := range s.Policy.Subject.InProcessName {
					self, err := state.deps.prog.GetBinaryId(process, true) // DNS policies do not include args for now
					if err != nil {
						logger.GetLogger().Warn("process policy remove error", logfields.Error, err)
						continue
					}

					processSrc := &types.ProcessTreeKey{
						WLID:  subject.WLID,
						Depth: 0,
						Self:  self,
						Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
					}
					records = append(records, record.DatapathRecord{
						PolicyUID: policy,
						Src:       processSrc,
						Endpoint:  ep,
						Action:    action,
					})
				}
				if len(s.Policy.Subject.InProcessName) == 0 {
					records = append(records, record.DatapathRecord{
						PolicyUID: policy,
						Src:       subject,
						Endpoint:  ep,
						Action:    action,
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
	coll := state.src.Collection(ml)
	if coll == nil {
		return records, nil
	}

	subject, err := state.deps.createObjectSrcKey(pod)
	if err != nil {
		return records, nil
	}

	for _, s := range coll {
		action := calculateAction(&s.Policy.Action)
		d := state.dst[s.Policy.PolicyUID]

		// serviceSelector policies populate state.Src (for subject matching) but
		// not state.Dst (since they use CIDR records from ServiceMap instead of
		// destination pod labels). Add nil check to prevent panic when removing
		// pods that match serviceSelector policy subjects.
		if d == nil {
			continue
		}

		for _, ep := range d.Endpoints {
			dpEndpoint := record.DatapathEndpoint{
				EP: ep,
			}

			if len(s.Policy.Subject.InProcessName) == 0 {
				records = append(records, record.DatapathRecord{
					PolicyUID: policy,
					Src:       subject,
					Endpoint:  dpEndpoint,
					Action:    action,
				})
			}
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := state.deps.prog.GetBinaryId(process, true) // DNS policies do not include args for now
				if err != nil {
					logger.GetLogger().Warn("pod remove endpoint binary id error", logfields.Error, err)
					continue
				}
				processSrc := &types.ProcessTreeKey{
					WLID:  subject.WLID,
					Depth: 0,
					Self:  self,
					Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
				}
				records = append(records, record.DatapathRecord{
					PolicyUID: policy,
					Src:       processSrc,
					Endpoint:  dpEndpoint,
					Action:    action,
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
			records = append(records, record.DatapathRecord{
				PolicyUID: policy,
				Src:       subject,
				Endpoint: record.DatapathEndpoint{
					EP:   nil,
					Port: 0,
				},
			})
		}

		if s.Policy.Destination.CIDR.IsValid() {
			r, err := state.deps.addDestCIDRRecords(
				policy,
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
			action := calculateAction(&s.Policy.Action)
			ep := &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  entry,
			}
			endpoint := record.DatapathEndpoint{
				EP:   ep,
				Port: 0,
			}
			for _, process := range s.Policy.Subject.InProcessName {
				self, err := state.deps.prog.GetBinaryId(process, true) // DNS policies do not include args for now
				if err != nil {
					logger.GetLogger().Warn("pod remove FQDN binary id error", logfields.Error, err)
					continue
				}
				processSrc := &types.ProcessTreeKey{
					WLID:  subject.WLID,
					Depth: 0,
					Self:  self,
					Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
				}

				records = append(records, record.DatapathRecord{
					PolicyUID: policy,
					Src:       processSrc,
					Endpoint:  endpoint,
					Action:    action,
				})
			}
			if len(s.Policy.Subject.InProcessName) == 0 {
				records = append(records, record.DatapathRecord{
					PolicyUID: policy,
					Src:       subject,
					Endpoint:  endpoint,
					Action:    action,
				})
			}
		}
	}
	delete(state.localObjects, pod.UID)
	return records, nil
}

func (state *PolicyState) PodRemove(pod *v1alpha1.PodInfo) error {
	state.mu.Lock()
	records, err := state.podRemove(pod)
	state.mu.Unlock()
	if err != nil {
		return err
	}
	return state.deps.prog.RemoveRecords(records)
}

func (state *PolicyState) endpointAdd(ep *endpoint.Endpoint, ml *matchLabels.LabelSet, newEP bool) []record.DatapathRecord {
	records := []record.DatapathRecord{}
	dests := state.dst.Collection(ml)

	for _, d := range dests {
		// Add endpoint of pod to list of destinations for this label selector
		if newEP {
			d.AddEndpoint(ep)
		}

		// For dest dest label selector we need to create src->dst binding
		// to do this walk all subjects and add the new dst. Merge conflicts
		// are resolved by BPF datapath.
		policyList := state.src[d.Policy.PolicyUID]
		policy := policyList.Policy.PolicyUID
		for _, subject := range policyList.Subjects {
			action := calculateAction(&policyList.Policy.Action)

			if len(policyList.Policy.Subject.InProcessName) > 0 {
				for _, process := range policyList.Policy.Subject.InProcessName {
					self, err := state.deps.prog.GetBinaryId(process, true) // DNS policies do not include args for now
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
							WLID:  subject.WLID,
							Depth: 0,
							Self:  self,
							Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
						}
						records = append(records, record.DatapathRecord{
							PolicyUID: policy,
							Src:       processSrc,
							Endpoint:  endpoint,
							Action:    action,
						})
					}
					for _, port := range policyList.Policy.Destination.Ports {
						endpoint := record.DatapathEndpoint{
							EP:   ep,
							Port: port,
						}
						processSrc := &types.ProcessTreeKey{
							WLID:  subject.WLID,
							Depth: 0,
							Self:  self,
							Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
						}
						records = append(records, record.DatapathRecord{
							PolicyUID: policy,
							Src:       processSrc,
							Endpoint:  endpoint,
							Action:    action,
						})
					}
				}
			} else {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}

				records = append(records, record.DatapathRecord{
					PolicyUID: policy,
					Src:       subject,
					Endpoint:  endpoint,
					Action:    action,
				})
			}
		}
	}
	return records
}

func (state *PolicyState) srcAdd(src *types.ProcessTreeKey, ml *matchLabels.LabelSet, newSrc bool) []record.DatapathRecord {
	records := []record.DatapathRecord{}
	subjects := state.src.Collection(ml)

	for _, s := range subjects {
		if newSrc {
			s.AddSubject(src)
		}
		sRecords, err := state.AddSrcPolicy(src, s.Policy, true)
		if err != nil {
			logger.GetLogger().Warn("ProgAddNetwork failed", logfields.Error, err, "src", src)
		}
		records = append(records, sRecords...)
	}

	return records
}

func (deps externalDeps) getNamespaceLabels(ns string) map[string]string {
	l := make(map[string]string)

	// Skip namespace label lookup for empty namespace (host-level processes)
	if ns == "" {
		return l
	}

	// Always include the metadata.name label (Kubernetes adds this automatically to namespaces)
	l["kubernetes.io/metadata.name"] = ns

	// If we have a k8s client, fetch all other namespace labels
	if deps.k8sReader != nil {
		namespace := &corev1.Namespace{}
		err := deps.k8sReader.Get(context.Background(), client.ObjectKey{Name: ns}, namespace)
		if err != nil {
			logger.GetLogger().Warn("failed to get namespace labels for namespaceSelector matching",
				"namespace", ns, logfields.Error, err)
			return l
		}

		// Add all namespace labels
		maps.Copy(l, namespace.Labels)
	} else {
		logger.GetLogger().Warn("k8sReader not set, cannot fetch namespace labels for namespaceSelector",
			"namespace", ns)
	}

	return l
}

// mergeNamespaceLabels returns a fresh map containing the pod's own labels
// merged with namespace labels prefixed with _tnp_. The result is the label
// set used for matchLabelsSubset against serviceSelector policy subjects that
// may include namespaceSelector constraints. A nil-labels pod is treated as
// an empty label set so that a policy whose subject is satisfied by namespace
// labels alone still matches.
func (deps externalDeps) mergeNamespaceLabels(obj metav1.Object) map[string]string {
	nsLabels := deps.getNamespaceLabels(obj.GetNamespace())
	src := obj.GetLabels()
	// Allocate a fresh map: the pod label map returned by obj.GetLabels() is
	// shared within the controller-runtime cache, so we must never mutate it.
	// Reads under another goroutine swapping the cached object are also safe
	// because we only iterate the snapshot returned above.
	dst := make(map[string]string, len(src)+len(nsLabels))
	for k, v := range src {
		// Drop any _tnp_-prefixed keys supplied by the pod itself: only
		// namespace labels are allowed to contribute under that prefix,
		// otherwise a pod could spoof a namespaceSelector by self-labeling
		// (similar class of bug we hit in cilium previously).
		if strings.HasPrefix(k, "_tnp_") {
			continue
		}
		dst[k] = v
	}
	for k, v := range nsLabels {
		dst["_tnp_"+k] = v
	}
	return dst
}

func (state *PolicyState) objectAdd(endpointObject metav1.Object) ([]record.DatapathRecord, error) {
	ml := &matchLabels.LabelSet{Labels: state.deps.mergeNamespaceLabels(endpointObject)}

	ep := createObjectEndpoint(endpointObject)

	epRecords := state.endpointAdd(ep, ml, true)

	src, err := state.deps.createObjectSrcKey(endpointObject)
	if err != nil {
		return epRecords, err
	}

	// If there is no local key it must be a remote pod
	if src == nil {
		state.remoteObjects[endpointObject.GetUID()] = endpointObject
		return epRecords, nil
	}

	srcRecords := state.srcAdd(src, ml, true)
	state.localObjects[endpointObject.GetUID()] = endpointObject
	return append(epRecords, srcRecords...), nil
}

// Top level handler to add pod and calculate tetragon network policy
func (state *PolicyState) PodAdd(epPod *v1alpha1.PodInfo) error {
	state.mu.Lock()
	records, err := state.objectAdd(epPod)
	if err != nil {
		state.mu.Unlock()
		return err
	}

	// Create serviceSelector records for this pod.
	svcSelRecords, err := state.createServiceSelectorRecords(epPod)
	state.mu.Unlock()
	if err != nil {
		logger.GetLogger().Warn("Failed to create serviceSelector records", logfields.Error, err)
	}
	records = append(records, svcSelRecords...)

	return state.deps.prog.AddRecords(records, false)
}
