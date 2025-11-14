package controller

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

const PolicyTableName = "policies"

type Result struct {
	Old, New types.Policy
	Diff     model.FlowDiff
}

type Summary struct {
	TargetGeneration  int64
	StagingGeneration int64
	AllowToDeny       int
	DenyToAllow       int
	Confidence        float64
	Sample            []string
}

func (r *Result) Summary(cfg Config) Summary {
	var sample []string
	for _, fd := range r.Diff.Flows[:min(10, len(r.Diff.Flows))] {
		sample = append(sample,
			fmt.Sprintf("%s | %s -> %s", fd.Flow.String(), fd.V1, fd.V2))
	}
	return Summary{
		TargetGeneration:  r.Old.Generation,
		StagingGeneration: r.New.Generation,
		AllowToDeny:       len(r.Diff.AllowToDeny),
		DenyToAllow:       len(r.Diff.DenyToAllow),
		Confidence:        r.Confidence(cfg),
		Sample:            sample,
	}
}
func (r *Result) SummaryString(cfg Config) string {
	b, _ := json.Marshal(r.Summary(cfg))
	return string(b)
}

var confidenceTable = []struct{ threshold, confidence float64 }{
	{0.0, 0.95}, // 0% changed => 95% confidence
	{0.01, 0.7}, // 1% changed => 70% confidence
	{0.05, 0.5}, // ...
	{0.1, 0.4},
	{0.2, 0.3},
}

func (r *Result) Confidence(cfg Config) float64 {
	if r.Diff.NumFlowsAnalyzed < cfg.ConfidenceMinConnections {
		// Not enough matched flows to make a call.
		return 0.0
	}
	verdictChangeRatio := float64(len(r.Diff.Flows)) / float64(r.Diff.NumFlowsAnalyzed)
	for _, e := range confidenceTable {
		if verdictChangeRatio <= e.threshold {
			return e.confidence
		}
	}
	return 0.0
}

type Policy struct {
	types.Policy

	Target string

	// ReconciledGeneration is the generation of the target for which the
	// results were produced.
	ReconciledGeneration int64

	ReconciledResult *Result

	Status reconciler.Status
}

func (p *Policy) Clone() *Policy {
	p2 := *p
	return &p2
}

// TableHeader implements statedb.TableWritable.
func (p *Policy) TableHeader() []string {
	return []string{"Name", "Target", "Result", "Status"}
}

// TableRow implements statedb.TableWritable.
func (p *Policy) TableRow() []string {
	var status string
	if p.Status.Kind != reconciler.StatusKindUnset {
		status = p.Status.String()
	}
	var result string
	if p.ReconciledResult != nil {
		r := p.ReconciledResult
		result = fmt.Sprintf("AllowToDeny: %d, DenyToAllow: %d", len(r.Diff.AllowToDeny), len(r.Diff.DenyToAllow))
	}
	return []string{p.Name, p.Target, result, status}
}

var _ statedb.TableWritable = &Policy{}

var (
	PolicyNameIndex = statedb.Index[*Policy, string]{
		Name: "name",
		FromObject: func(obj *Policy) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	PolicyByName = PolicyNameIndex.Query

	PolicyTargetIndex = statedb.Index[*Policy, string]{
		Name: "target",
		FromObject: func(obj *Policy) index.KeySet {
			return index.NewKeySet(index.String(obj.Target))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	PoliciesByTarget = PolicyTargetIndex.Query
)

func NewPolicyTable(db *statedb.DB) (statedb.Table[*Policy], statedb.RWTable[*Policy], error) {
	tbl, err := statedb.NewTable(
		db,
		PolicyTableName,
		PolicyNameIndex,
	)
	return tbl, tbl, err
}
