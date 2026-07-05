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

package netpol

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

func npCR(name string, uid k8stypes.UID, generation int64) *v1alpha1.TetragonNetworkPolicy {
	return &v1alpha1.TetragonNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid, Generation: generation},
	}
}

func seedStory(t *testing.T, title string, uid k8stypes.UID, generation int64) {
	t.Helper()
	library.GetRepository().Add(&library.PolicyStory{
		Title:     title,
		CRDPolicy: npCR(title, uid, generation),
	})
	t.Cleanup(func() { library.GetRepository().Delete(title) })
}

type stateRecorder struct {
	applyCalls   int
	unapplyCalls int
	applyErr     error
	unapplyErr   error
}

func stubState(t *testing.T) *stateRecorder {
	t.Helper()
	rec := &stateRecorder{}
	prevApply, prevUnapply := applyPolicies, unapplyPolicies
	applyPolicies = func([]*types.TetragonNetworkPolicy) error {
		rec.applyCalls++
		return rec.applyErr
	}
	unapplyPolicies = func([]*types.TetragonNetworkPolicy) error {
		rec.unapplyCalls++
		return rec.unapplyErr
	}
	t.Cleanup(func() { applyPolicies, unapplyPolicies = prevApply, prevUnapply })
	return rec
}

func TestPlanUpsert(t *testing.T) {
	t.Run("fresh add loads under canonical name", func(t *testing.T) {
		got := planUpsert(npCR("np-fresh", "u1", 1))
		require.Equal(t, npAdd, got.action)
		require.Equal(t, "np-fresh", got.target)
	})

	t.Run("same UID and generation is a no-op", func(t *testing.T) {
		seedStory(t, "np-noop", "u1", 3)
		got := planUpsert(npCR("np-noop", "u1", 3))
		require.Equal(t, npNoop, got.action)
	})

	t.Run("same UID and generation with leftover alt slot clears it", func(t *testing.T) {
		seedStory(t, "np-left", "u1", 3)
		seedStory(t, "__np-left", "u0", 2)
		got := planUpsert(npCR("np-left", "u1", 3))
		require.Equal(t, npDelete, got.action)
		require.Equal(t, "__np-left", got.victim)
	})

	t.Run("changed generation swaps canonical -> alt", func(t *testing.T) {
		seedStory(t, "np-canon", "u1", 1)
		got := planUpsert(npCR("np-canon", "u1", 2))
		require.Equal(t, npSwap, got.action)
		require.Equal(t, "__np-canon", got.target, "new version is staged under the alternate slot")
		require.Equal(t, "np-canon", got.victim, "old canonical slot is unloaded")
	})

	t.Run("changed UID at same generation swaps (delete+recreate)", func(t *testing.T) {
		seedStory(t, "np-recreate", "u-old", 1)
		got := planUpsert(npCR("np-recreate", "u-new", 1))
		require.Equal(t, npSwap, got.action, "a recreated CR must be swapped in, not skipped")
	})

	t.Run("story without a CR identity swaps (file/gRPC-loaded)", func(t *testing.T) {
		library.GetRepository().Add(&library.PolicyStory{Title: "np-grpc"})
		t.Cleanup(func() { library.GetRepository().Delete("np-grpc") })
		got := planUpsert(npCR("np-grpc", "u1", 1))
		require.Equal(t, npSwap, got.action, "the CR displaces a non-CR policy of the same name")
	})

	t.Run("changed generation swaps alt -> canonical", func(t *testing.T) {
		seedStory(t, "__np-alt", "u1", 1)
		got := planUpsert(npCR("np-alt", "u1", 2))
		require.Equal(t, npSwap, got.action)
		require.Equal(t, "np-alt", got.target)
		require.Equal(t, "__np-alt", got.victim)
	})
}

func TestPlanDelete(t *testing.T) {
	t.Run("unloads the currently-held slot", func(t *testing.T) {
		seedStory(t, "np-del", "u1", 1)
		got := planDelete("np-del")
		require.Equal(t, npDelete, got.action)
		require.Equal(t, "np-del", got.victim)
	})

	t.Run("unloads the alt slot when only it is held", func(t *testing.T) {
		seedStory(t, "__np-del-alt", "u1", 1)
		got := planDelete("np-del-alt")
		require.Equal(t, npDelete, got.action)
		require.Equal(t, "__np-del-alt", got.victim)
	})

	t.Run("no-op when nothing is loaded", func(t *testing.T) {
		got := planDelete("np-absent")
		require.Equal(t, npNoop, got.action)
	})
}

func reconcileNP(t *testing.T, name string, objs ...*v1alpha1.TetragonNetworkPolicy) (ctrl.Result, error) {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(newTestScheme(t))
	for _, o := range objs {
		builder = builder.WithObjects(o)
	}
	r := &TetragonNetworkPolicyReconciler{Client: builder.Build()}
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: name},
	})
}

func TestNPReconcile_Found_Adds(t *testing.T) {
	rec := stubState(t)
	t.Cleanup(func() { library.GetRepository().Delete("np-r-add") })

	_, err := reconcileNP(t, "np-r-add", npCR("np-r-add", "u1", 1))
	require.NoError(t, err)
	require.Equal(t, 1, rec.applyCalls)
	require.NotNil(t, library.GetRepository().Get("np-r-add"), "repository holds the loaded policy")
}

func TestNPReconcile_Found_ApplyError_RollsBackAndRequeues(t *testing.T) {
	rec := stubState(t)
	rec.applyErr = errors.New("datapath down")

	_, err := reconcileNP(t, "np-r-addfail", npCR("np-r-addfail", "u1", 1))
	require.ErrorIs(t, err, rec.applyErr, "apply failure must requeue, not be swallowed")
	require.Nil(t, library.GetRepository().Get("np-r-addfail"),
		"failed load must roll the repository entry back so the retry starts clean")
}

func TestNPReconcile_Found_SameGeneration_IsNoop(t *testing.T) {
	rec := stubState(t)
	seedStory(t, "np-r-noop", "u1", 2)

	_, err := reconcileNP(t, "np-r-noop", npCR("np-r-noop", "u1", 2))
	require.NoError(t, err)
	require.Zero(t, rec.applyCalls)
	require.Zero(t, rec.unapplyCalls)
}

func TestNPReconcile_Found_NewGeneration_SwapsGapFree(t *testing.T) {
	rec := stubState(t)
	seedStory(t, "np-r-swap", "u1", 1)
	t.Cleanup(func() { library.GetRepository().Delete("__np-r-swap") })

	_, err := reconcileNP(t, "np-r-swap", npCR("np-r-swap", "u1", 2))
	require.NoError(t, err)
	require.Equal(t, 1, rec.applyCalls, "new version programmed")
	require.Equal(t, 1, rec.unapplyCalls, "old version unloaded")
	require.Nil(t, library.GetRepository().Get("np-r-swap"), "victim slot cleared")
	require.NotNil(t, library.GetRepository().Get("__np-r-swap"), "new version staged in alt slot")
	require.Equal(t, int64(2), library.GetRepository().Get("__np-r-swap").CRDPolicy.Generation)
}

func TestNPReconcile_Swap_ApplyError_KeepsVictimAndRequeues(t *testing.T) {
	rec := stubState(t)
	rec.applyErr = errors.New("datapath down")
	seedStory(t, "np-r-swapfail", "u1", 1)

	_, err := reconcileNP(t, "np-r-swapfail", npCR("np-r-swapfail", "u1", 2))
	require.ErrorIs(t, err, rec.applyErr)
	require.Zero(t, rec.unapplyCalls, "old policy must not be unloaded when the new one failed to apply")
	require.NotNil(t, library.GetRepository().Get("np-r-swapfail"), "old version stays enforced")
	require.Nil(t, library.GetRepository().Get("__np-r-swapfail"), "staged entry rolled back")
}

func TestNPReconcile_Swap_VictimUnloadError_Requeues(t *testing.T) {
	rec := stubState(t)
	rec.unapplyErr = errors.New("unload failed")
	seedStory(t, "np-r-swapdel", "u1", 1)
	t.Cleanup(func() { library.GetRepository().Delete("__np-r-swapdel") })

	_, err := reconcileNP(t, "np-r-swapdel", npCR("np-r-swapdel", "u1", 2))
	require.ErrorIs(t, err, rec.unapplyErr, "failed victim unload must requeue")
	require.NotNil(t, library.GetRepository().Get("np-r-swapdel"), "victim stays until the retry clears it")
	require.NotNil(t, library.GetRepository().Get("__np-r-swapdel"), "new version stays loaded")
}

func TestNPReconcile_Swap_RetryAfterVictimUnloadError_SkipsReapply(t *testing.T) {
	rec := stubState(t)
	seedStory(t, "np-r-retry", "u1", 1)
	t.Cleanup(func() { library.GetRepository().Delete("__np-r-retry") })
	cr := npCR("np-r-retry", "u1", 2)

	// First swap: victim unload fails, leaving both slots loaded.
	rec.unapplyErr = errors.New("unload failed")
	_, err := reconcileNP(t, "np-r-retry", cr)
	require.ErrorIs(t, err, rec.unapplyErr)
	require.Equal(t, 1, rec.applyCalls)

	// Retry: the target already holds the correct version, so no re-apply.
	rec.unapplyErr = nil
	_, err = reconcileNP(t, "np-r-retry", cr)
	require.NoError(t, err)
	require.Equal(t, 1, rec.applyCalls, "must not re-apply the already-correct target on retry")
	require.Equal(t, 2, rec.unapplyCalls, "victim unload retried")
	require.Nil(t, library.GetRepository().Get("np-r-retry"), "victim slot cleared")
	require.NotNil(t, library.GetRepository().Get("__np-r-retry"), "new version remains enforced")
}

func TestNPReconcile_NotFound_DeletesAllSlots(t *testing.T) {
	rec := stubState(t)
	seedStory(t, "np-r-del", "u1", 1)
	seedStory(t, "__np-r-del", "u1", 2)

	_, err := reconcileNP(t, "np-r-del")
	require.NoError(t, err)
	require.Equal(t, 2, rec.unapplyCalls, "both slots unloaded")
	require.Nil(t, library.GetRepository().Get("np-r-del"))
	require.Nil(t, library.GetRepository().Get("__np-r-del"))
}

func TestNPReconcile_NotFound_UnloadError_Requeues(t *testing.T) {
	rec := stubState(t)
	rec.unapplyErr = errors.New("unload failed")
	seedStory(t, "np-r-delfail", "u1", 1)

	_, err := reconcileNP(t, "np-r-delfail")
	require.ErrorIs(t, err, rec.unapplyErr)
	require.NotNil(t, library.GetRepository().Get("np-r-delfail"),
		"repository entry retained so the requeued delete can retry")
}

func TestNPReconcile_ConvertError_IsTerminal(t *testing.T) {
	rec := stubState(t)
	np := npCR("np-r-badspec", "u1", 1)
	np.Spec.Rules = []v1alpha1.NetworkPolicyRule{{Hook: "bogus"}}

	_, err := reconcileNP(t, "np-r-badspec", np)
	require.Error(t, err)
	require.ErrorIs(t, err, reconcile.TerminalError(nil), "invalid spec must not requeue")
	require.Zero(t, rec.applyCalls)
	require.Nil(t, library.GetRepository().Get("np-r-badspec"))
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

func TestRegisterTetragonNetworkPolicyReconciler_GatesOnCorrectCRD(t *testing.T) {
	cm := &fakeControllerManager{}
	require.NoError(t, RegisterTetragonNetworkPolicyReconciler(cm))
	require.Equal(t, enterpriseClient.TetragonNetworkPolicyCRD.ResName, cm.gotCRD)
	require.NotNil(t, cm.setup, "setup callback must be wired")
}
