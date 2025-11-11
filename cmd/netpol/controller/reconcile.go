package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/timescape"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

func registerPolicyReconciler(
	lc cell.Lifecycle,
	cfg Config,
	mngr ctrl.Manager,
	params reconciler.Params,
	tsClient *timescape.Client,
	policies statedb.RWTable[*Policy],
) error {
	ops, err := newPolicyOps(params.Log, cfg, mngr, tsClient, policies)
	if err != nil {
		return err
	}
	_, err = reconciler.Register(
		params,
		policies,
		(*Policy).Clone,
		func(r *Policy, s reconciler.Status) *Policy {
			r.Status = s
			return r
		},
		func(r *Policy) reconciler.Status {
			return r.Status
		},
		ops,
		nil,

		// Use fairly aggressive backoff on failures.
		reconciler.WithRetry(
			10*time.Second,
			5*time.Minute,
		),
	)
	return err
}

type policyOps struct {
	cfg      Config
	log      *slog.Logger
	tsClient *timescape.Client
	client   rest.Interface
	policies statedb.Table[*Policy]
}

// Delete implements reconciler.Operations.
func (r *policyOps) Delete(context.Context, statedb.ReadTxn, statedb.Revision, *Policy) error {
	return nil
}

// Prune implements reconciler.Operations.
func (r *policyOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*Policy, statedb.Revision]) error {
	return nil
}

// Update implements reconciler.Operations.
func (r *policyOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, policy *Policy) error {
	if policy.Target == "" {
		return nil
	}

	result, err := r.validatePolicy(ctx, txn, policy)
	if err != nil {
		return err
	}
	if result.Old.Name == "" {
		// Target policy doesn't exist yet, do nothing until it appears.
		return nil
	}

	type jp struct {
		OP    string `json:"op,omitempty"`
		Path  string `json:"path,omitempty"`
		Value any    `json:"value"`
	}
	path := fmt.Sprintf("/metadata/annotations/%s~1validation", v1alpha1.SNPName)

	jsonPatch := []jp{
		{
			OP:    "replace",
			Path:  path,
			Value: result.SummaryString(),
		},
	}
	patch, _ := json.Marshal(jsonPatch)
	namespace, name, _ := strings.Cut(policy.Name, "/")
	doResult := r.client.Patch(k8sTypes.JSONPatchType).
		Resource(v1alpha1.SNPPluralName).
		Namespace(namespace).
		Name(name).
		Body(patch).
		Do(ctx)

	var code int
	doResult.StatusCode(&code)
	r.log.Info(
		"Update",
		"result", result.SummaryString(),
		"error", doResult.Error(),
		"warnings", doResult.Warnings(),
		"code", code,
	)
	return doResult.Error()
}

var _ reconciler.Operations[*Policy] = &policyOps{}

func newPolicyOps(log *slog.Logger, cfg Config, mngr ctrl.Manager, tsClient *timescape.Client, policies statedb.Table[*Policy]) (*policyOps, error) {
	restConfig := *mngr.GetConfig()
	restConfig.APIPath = "/apis"
	restConfig.GroupVersion = &v1alpha1.SchemeGroupVersion
	restConfig.NegotiatedSerializer = serializer.NewCodecFactory(v1alpha1Scheme)
	client, err := rest.RESTClientForConfigAndClient(
		&restConfig,
		mngr.GetHTTPClient(),
	)
	if err != nil {
		return nil, err
	}
	return &policyOps{
		log:      log,
		cfg:      cfg,
		client:   client,
		tsClient: tsClient,
		policies: policies,
	}, err
}

func (r *policyOps) validatePolicy(
	ctx context.Context,
	txn statedb.ReadTxn,
	policy *Policy,
) (Result, error) {
	targetName := policy.Target

	// Get the target policy
	target, _, found := r.policies.Get(txn, PolicyByName(targetName))
	if !found {
		// Policy doesn't exist yet, do nothing.
		r.log.Info("Target policy does not exist yet, skipping", "policy", policy.Name, "target", targetName)
		return Result{}, nil
	}
	policy.ReconciledGeneration = target.Generation

	// Construct the base policy
	// TODO: Could consider just doing iterators for rules to avoid
	// building up these slices.
	var basePolicy types.Policy
	for p := range r.policies.All(txn) {
		// Skip staging policies and the policy that we're targeting.
		if p.Target != "" || p.Name == targetName {
			continue
		}
		basePolicy.Rules = append(basePolicy.Rules, p.Rules...)
	}

	old, new, filter := model.ComputeMinimal(
		basePolicy,
		target.Policy,
		policy.Policy)

	until := time.Now()
	since := until.Add(-r.cfg.Duration)

	r.log.Info("Retrieving connections", "time-range", until.Sub(since), "filter", timescape.FilterToCEL(filter))

	conns, err := r.tsClient.GetConnections(
		ctx,
		since,
		until,
		filter,
	)
	if err != nil {
		r.log.Error("Error retrieving connections", "error", err, "since", since, "until", until, "filter", filter)
		return Result{}, err
	}

	m1, err := model.NewModel(types.Policy{Rules: old})
	if err != nil {
		r.log.Error("Error constructing model", "error", err)
		return Result{}, err
	}
	m2, err := model.NewModel(types.Policy{Rules: new})
	if err != nil {
		r.log.Error("Error constructing model", "error", err)
		return Result{}, err
	}
	diff := model.Diff(m1, m2, conns)

	policy.ReconciledResult = &Result{Old: target.Policy, New: policy.Policy, Diff: diff}
	return *policy.ReconciledResult, nil
}
