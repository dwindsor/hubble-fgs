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

package watcher

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type fakeSensors struct {
	addCalls    []addCall
	deleteCalls []deleteCall
	addErr      error
	deleteErr   error
}

type addCall struct {
	name      string
	namespace string
}

type deleteCall struct {
	name      string
	namespace string
}

func (f *fakeSensors) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	f.addCalls = append(f.addCalls, addCall{tp.TpName(), tp.TpNamespace()})
	return f.addErr
}

func (f *fakeSensors) DeleteTracingPolicy(_ context.Context, name, namespace, _ string) error {
	f.deleteCalls = append(f.deleteCalls, deleteCall{name, namespace})
	return f.deleteErr
}

type fakeTP struct {
	name      string
	namespace string
}

func (f fakeTP) TpName() string                      { return f.name }
func (f fakeTP) TpNamespace() string                 { return f.namespace }
func (f fakeTP) TpInfo() string                      { return f.name }
func (f fakeTP) TpDomain() string                    { return "sandbox" }
func (f fakeTP) TpSpec() *v1alpha1.TracingPolicySpec { return nil }

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}

type reconcilerKind struct {
	name              string
	crdName           string
	newObject         func(name string) client.Object
	request           ctrl.Request
	expectedNamespace string
	newReconciler     func(cli client.Client, s sensorManager, convertErr error) reconcile.Reconciler
	register          func(controllerManager, sensorManager) error
}

func reconcilerKinds() []reconcilerKind {
	return []reconcilerKind{
		{
			name:    "cluster_scoped",
			crdName: enterpriseClient.SandboxPolicyCRD.ResName,
			newObject: func(name string) client.Object {
				return &v1alpha1.SandboxPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "SandboxPolicy",
						APIVersion: "cilium.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: name},
				}
			},
			request:           ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}},
			expectedNamespace: "",
			newReconciler: func(cli client.Client, s sensorManager, convertErr error) reconcile.Reconciler {
				return &SandboxPolicyReconciler{
					Client:  cli,
					Sensors: s,
					convert: func(sp *v1alpha1.SandboxPolicy) (tracingpolicy.TracingPolicy, error) {
						if convertErr != nil {
							return nil, convertErr
						}
						return fakeTP{name: sp.Name}, nil
					},
				}
			},
			register: RegisterSandboxPolicyReconciler,
		},
		{
			name:    "namespaced",
			crdName: enterpriseClient.SandboxPolicyNamespacedCRD.ResName,
			newObject: func(name string) client.Object {
				return &v1alpha1.SandboxPolicyNamespaced{
					TypeMeta: metav1.TypeMeta{
						Kind:       "SandboxPolicyNamespaced",
						APIVersion: "cilium.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
				}
			},
			request:           ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1", Namespace: "team-a"}},
			expectedNamespace: "team-a",
			newReconciler: func(cli client.Client, s sensorManager, convertErr error) reconcile.Reconciler {
				return &SandboxPolicyNamespacedReconciler{
					Client:  cli,
					Sensors: s,
					convert: func(sp *v1alpha1.SandboxPolicyNamespaced) (tracingpolicy.TracingPolicy, error) {
						if convertErr != nil {
							return nil, convertErr
						}
						return fakeTP{name: sp.Name, namespace: sp.Namespace}, nil
					},
				}
			},
			register: RegisterSandboxPolicyNamespacedReconciler,
		},
	}
}

func TestReconcile_NotFound_CallsDelete(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
			r := k.newReconciler(cli, sensors, nil)

			res, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, res)

			require.Len(t, sensors.deleteCalls, 1)
			require.Equal(t, k.request.Name, sensors.deleteCalls[0].name)
			require.Equal(t, k.expectedNamespace, sensors.deleteCalls[0].namespace)
			require.Empty(t, sensors.addCalls, "no Add on NotFound")
		})
	}
}

func TestReconcile_Found_CallsDeleteThenAdd(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sp := k.newObject(k.request.Name)
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(sp).
				Build()
			r := k.newReconciler(cli, sensors, nil)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)

			require.Len(t, sensors.deleteCalls, 1)
			require.Equal(t, k.request.Name, sensors.deleteCalls[0].name)
			require.Equal(t, k.expectedNamespace, sensors.deleteCalls[0].namespace)

			require.Len(t, sensors.addCalls, 1)
			require.Equal(t, k.request.Name, sensors.addCalls[0].name)
			require.Equal(t, k.expectedNamespace, sensors.addCalls[0].namespace)
		})
	}
}

func TestReconcile_GetError_PropagatesAndDoesNothing(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			wantErr := errors.New("boom")
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
						return wantErr
					},
				}).
				Build()
			r := k.newReconciler(cli, sensors, nil)

			_, err := r.Reconcile(context.Background(), k.request)
			require.ErrorIs(t, err, wantErr)
			require.Empty(t, sensors.addCalls)
			require.Empty(t, sensors.deleteCalls)
		})
	}
}

func TestReconcile_DeleteError_DoesNotBlockAdd(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sp := k.newObject(k.request.Name)
			sensors := &fakeSensors{deleteErr: errors.New("not in collection -- fine")}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(sp).
				Build()
			r := k.newReconciler(cli, sensors, nil)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Len(t, sensors.deleteCalls, 1)
			require.Len(t, sensors.addCalls, 1, "delete-before-add error must not skip the Add")
		})
	}
}

func TestReconcile_ConvertError_SkipsAdd(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sp := k.newObject(k.request.Name)
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(sp).
				Build()
			r := k.newReconciler(cli, sensors, errors.New("bad spec"))

			_, err := r.Reconcile(context.Background(), k.request)
			require.ErrorIs(t, err, reconcile.TerminalError(nil))
			require.Len(t, sensors.deleteCalls, 1)
			require.Empty(t, sensors.addCalls, "conversion failure must skip Add")
		})
	}
}

func TestReconcile_AddError_ReturnsTerminal(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sp := k.newObject(k.request.Name)
			sensors := &fakeSensors{addErr: errors.New("bpf load failed")}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(sp).
				Build()
			r := k.newReconciler(cli, sensors, nil)

			_, err := r.Reconcile(context.Background(), k.request)
			require.ErrorIs(t, err, sensors.addErr)
			require.ErrorIs(t, err, reconcile.TerminalError(nil))
			require.Len(t, sensors.addCalls, 1, "add was attempted")
		})
	}
}

type fakeControllerManager struct {
	gotCRD string
	setup  func(ctrl.Manager) error
}

func (f *fakeControllerManager) RegisterControllerWhenCRDReady(crdName string, setup func(ctrl.Manager) error) error {
	f.gotCRD = crdName
	f.setup = setup
	return nil
}

func TestRegisterReconciler_GatesOnCorrectCRD(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			cm := &fakeControllerManager{}
			require.NoError(t, k.register(cm, &fakeSensors{}))
			require.Equal(t, k.crdName, cm.gotCRD)
			require.NotNil(t, cm.setup, "setup callback must be wired")
		})
	}
}
