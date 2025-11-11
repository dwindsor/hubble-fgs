package controller

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
)

func registerPopulatePolicyTable(
	log *slog.Logger,
	db *statedb.DB,
	tbl statedb.RWTable[*Policy],
	jg job.Group,
	mngr ctrl.Manager,
) {
	jg.Add(
		job.OneShot("populate-policies", func(ctx context.Context, health cell.Health) error {
			if err := waitForCRDs(ctx, log, mngr, v1alpha1.SNPName); err != nil {
				return err
			}
			informer, err := mngr.GetCache().GetInformer(ctx, &v1alpha1.SmartSwitchNetworkPolicy{})
			if err != nil {
				return fmt.Errorf("failed to get informer: %w", err)
			}
			handler := &handler{log: log, db: db, policies: tbl}
			_, err = informer.AddEventHandler(
				cache.ResourceEventHandlerFuncs{
					AddFunc:    handler.addOrUpdatePolicy,
					UpdateFunc: func(oldObj any, newObj any) { handler.addOrUpdatePolicy(newObj) },
					DeleteFunc: handler.deletePolicy,
				})
			if err != nil {
				return err
			}
			// Wait until we're stopping. This is here mostly to avoid the informer deregistration
			// in [waitForCRDs] to log errors when the [ctx] is cancelled too early.
			<-ctx.Done()
			return nil
		}, job.WithShutdown()))
}

type handler struct {
	log      *slog.Logger
	db       *statedb.DB
	policies statedb.RWTable[*Policy]
}

func (h *handler) addOrUpdatePolicy(obj any) {
	np, ok := obj.(*v1alpha1.SmartSwitchNetworkPolicy)
	if !ok {
		panic("unexpected, object not SmartSwitchNetworkPolicy")
	}

	policy := &Policy{}
	var err error
	policy.Policy, err = types.ConvertSmartSwitchNetworkPolicy(np)
	if err != nil {
		h.log.Error("Skipping malformed policy", "name", np.Name, "namespace", np.Namespace, "error", err)
		return
	}

	wtxn := h.db.WriteTxn(h.policies)
	defer wtxn.Commit()

	targetPolicy, found := np.GetAnnotations()[stagingAnnotation]
	if found {
		policy.Target = np.Namespace + "/" + targetPolicy

		// Only update the policy if it's new or that the generation has changed.
		// This ensures we don't end up looping when the annotation is updated
		// (generation only updates on spec changes)
		p, _, found := h.policies.Get(wtxn, PolicyByName(policy.Name))
		if !found || policy.Generation > p.Generation {
			policy.Status = reconciler.StatusPending()
			policy.ReconciledGeneration = 0
			h.policies.Insert(wtxn, policy)
		}
	} else {
		// Mark all staging policies targeting this for reconciliation.
		for p := range h.policies.List(wtxn, PoliciesByTarget(policy.Name)) {
			if p.ReconciledGeneration != policy.Generation {
				p2 := *p
				p2.Status = reconciler.StatusPending()
				h.policies.Insert(wtxn, &p2)
			}
		}
		h.policies.Insert(wtxn, policy)
	}

	h.log.Info("Updated policy", "name", policy.Name)
}

func (h *handler) deletePolicy(obj any) {
	var namespace, name string
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		namespace, name, _ = cache.SplitMetaNamespaceKey(d.Key)
	} else {
		meta, err := meta.Accessor(obj)
		if err != nil {
			return
		}
		namespace = meta.GetNamespace()
		name = meta.GetName()
	}
	p := types.Policy{Name: namespace + "/" + name}

	wtxn := h.db.WriteTxn(h.policies)
	h.policies.Delete(wtxn, &Policy{Policy: p})
	wtxn.Commit()
	h.log.Info("Deleted policy", "name", p.Name)
}

const stagingAnnotation = v1alpha1.SNPName + "/staging"
